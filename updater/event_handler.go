package updater

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	rabbithole "github.com/michaelklishin/rabbit-hole/v3"
	"gopkg.in/ini.v1"
)

const (
	userFilePrefix   = "user_"
	adminFileSection = "default"
	adminUserID      = "admin"
)

// UserCredentials holds the plain‐text credentials read from a secret file group.
type UserCredentials struct {
	Username string
	Password string
	Tag      string
}

// PasswordUpdater now uses a WatchDir instead of single default configuration file.
// CredentialState stores the last successfully verified user credentials.
// CredentialSpec stores the expected user credentials.
type PasswordUpdater struct {
	AdminFile       string
	Watcher         *fsnotify.Watcher
	WatchDir        string
	Done            chan<- bool
	Log             logr.Logger
	adminClient     RabbitClient
	authClient      RabbitClient
	CredentialState map[string]UserCredentials
	CredentialSpec  map[string]UserCredentials
}

type RabbitClient interface {
	// RabbitMQ Management API functions
	GetUser(username string) (*rabbithole.UserInfo, error)
	PutUser(username string, settings rabbithole.UserSettings) (*http.Response, error)
	Whoami() (*rabbithole.WhoamiInfo, error)

	// Credential management functions
	GetUsername() string
	SetUsername(username string)
	SetPassword(password string)
}

// HandleEvents continuously waits for file system events and processes secrets when any file
// matching the expected pattern is changed.
func (u *PasswordUpdater) HandleEvents() {
	defer u.Watcher.Close()

	for {
		select {
		case event, ok := <-u.Watcher.Events:
			if !ok {
				u.Log.V(0).Info("watcher events channel is closed, exiting...", "directory", u.WatchDir)
				u.Done <- true
				return
			}
			u.Log.V(4).Info("file system event", "file", event.Name, "operation", event.Op.String())
			if isSecretFile(event.Name) {
				if err := u.processSecrets(); err != nil {
					u.Log.Error(err, "failed to process secrets")
					u.Done <- true
					return
				}
			}
		case err, ok := <-u.Watcher.Errors:
			if !ok {
				u.Log.V(0).Info("watcher errors channel is closed, exiting...")
				u.Done <- true
				return
			}
			u.Log.Error(err, "failed to watch", "directory", u.WatchDir)
		}
	}
}

// isSecretFile returns true if the base name starts with "user_".
func isSecretFile(filePath string) bool {
	base := filepath.Base(filePath)
	return strings.HasPrefix(base, userFilePrefix)
}

// processSecrets reads all files in WatchDir, groups them by user ID (based on file names),
// and then (using admin credentials) updates every user whose password has changed.
func (u *PasswordUpdater) processSecrets() error {
	// Explicitly set admin credentials from state before processing secrets
	u.adminClient.SetUsername(u.CredentialState[adminUserID].Username)
	u.adminClient.SetPassword(u.CredentialState[adminUserID].Password)

	files, err := os.ReadDir(u.WatchDir)
	if err != nil {
		return err
	}

	secretFiles := make(map[string][]byte)
	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), userFilePrefix) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(u.WatchDir, file.Name()))
		if err != nil {
			u.Log.Error(err, "failed to read secret file", "file", file.Name())
			return err
		}
		secretFiles[file.Name()] = content
	}

	secrets := make(map[string]map[string]string)
	for name, contentBytes := range secretFiles {
		remainder := name[len(userFilePrefix):]
		parts := strings.SplitN(remainder, "_", 2)
		if len(parts) != 2 {
			u.Log.V(1).Info("ignoring file with unexpected name format", "file", name)
			continue
		}
		userName, key := parts[0], parts[1]
		value := strings.TrimSpace(string(contentBytes))
		if _, exists := secrets[userName]; !exists {
			secrets[userName] = make(map[string]string)
		}
		secrets[userName][key] = value
	}

	var userNames []string
	for userID := range secrets {
		userNames = append(userNames, userID)
	}
	sort.Strings(userNames)

	for _, userID := range userNames {
		data := secrets[userID]
		username, hasUsername := data["username"]
		password, hasPassword := data["password"]
		tag, hasTag := data["tag"]

		if state, exists := u.CredentialState[username]; exists &&
			state.Password == password && state.Tag == tag {
			u.Log.V(4).Info("credentials unchanged, skipping update", "user", username)
			continue
		}

		if !hasUsername || !hasPassword || strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
			u.Log.Error(err, "incomplete or empty credentials for user", "user", userID)
			return fmt.Errorf("incomplete or empty credentials for user %s", userID)
		}
		if !hasTag {
			tag = ""
		}

		if userID == adminUserID {
			// Verify that we can authenticate with the current admin credentials
			if err := u.authenticate(u.adminClient); err != nil {
				u.Log.Error(err, "failed to authenticate with current admin credentials", "user", username)
				return fmt.Errorf("failed to authenticate with current admin credentials: %w", err)
			}

			// If admin username has changed, verify we can still authenticate
			// with current credentials before proceeding with the update
			currentAdminUser := u.adminClient.GetUsername()
			if currentAdminUser != username {
				u.Log.V(1).Info("admin username changed", "old", currentAdminUser, "new", username)
				if err := u.authenticate(u.adminClient); err != nil {
					u.Log.Error(err, "failed to authenticate with current admin credentials", "user", username)
					return fmt.Errorf("failed to authenticate with current admin credentials: %w", err)
				}
			}
		}

		newCred := UserCredentials{
			Username: username,
			Password: password,
			Tag:      tag,
		}

		// Update credentials in RabbitMQ
		if err := u.updateInRabbitMQ(newCred, u.CredentialSpec); err != nil {
			u.Log.Error(err, "failed to update credentials in RabbitMQ for user", "user", username)
			break
		}
		// Update credentials state, so that we can skip the next update if the credentials haven't changed
		u.CredentialState[username] = newCred
		// Update admin RabbitMQ client credentials
		u.adminClient.SetUsername(u.CredentialState[adminUserID].Username)
		u.adminClient.SetPassword(u.CredentialState[adminUserID].Password)

		if userID == adminUserID {
			// Update admin credentials file, eg /var/lib/rabbitmq/.rabbitmqadmin.conf
			// Check whether the current admin file are up-to-date.
			correct, err := u.checkAdminFile(newCred)
			if err != nil {
				u.Log.Error(err, "failed to load admin credentials file", "file", u.AdminFile)
			}
			if !correct {
				if err := u.updateAdminFile(newCred); err != nil {
					u.Log.Error(err, "failed to update RabbitMQ admin credentials file", "user", username)
				} else {
					u.Log.V(1).Info("updated admin credentials file", "file", u.AdminFile)
				}
			} else {
				u.Log.V(1).Info("admin credentials file is already up-to-date, no update needed", "file", u.AdminFile)
			}
			// Verification: re-authenticate after updating admin credentials
			if err := u.authenticate(u.adminClient); err != nil {
				u.Log.Error(err, "extra admin step: failed to re-authenticate after updating admin credentials", "user", username)
			} else {
				u.Log.V(1).Info("extra admin step: re-authentication successful for admin", "user", username)
			}
		}
	}
	return nil
}

// updateInRabbitMQ tries to update a user's password (and tag) on the RabbitMQ server.
func (u *PasswordUpdater) updateInRabbitMQ(cred UserCredentials, spec map[string]UserCredentials) error {
	pathUsers := "/api/users/" + cred.Username

	var user *rabbithole.UserInfo
	var err error
	user, err = u.adminClient.GetUser(cred.Username)
	if err != nil {
		return u.handleHTTPError(u.adminClient, err, http.MethodGet, pathUsers, spec[adminUserID].Password)
	}
	hashingAlgorithm := rabbithole.HashingAlgorithmSHA256
	if user != nil {
		hashingAlgorithm = user.HashingAlgorithm
	}

	newUserSettings := rabbithole.UserSettings{
		Name:             cred.Username,
		Tags:             rabbithole.UserTags{cred.Tag},
		Password:         cred.Password,
		HashingAlgorithm: hashingAlgorithm,
	}
	resp, err := u.adminClient.PutUser(cred.Username, newUserSettings)
	if err != nil {
		return u.handleHTTPError(u.adminClient, err, http.MethodPut, pathUsers, spec[adminUserID].Password)
	}
	u.Log.V(2).Info("HTTP response", "method", http.MethodPut, "path", pathUsers, "status", resp.Status)
	u.Log.V(1).Info("updated password on RabbitMQ server", "user", cred.Username)
	return nil
}

func (u *PasswordUpdater) handleHTTPError(client RabbitClient, err error, httpMethod, pathUsers, newPasswd string) error {
	// as returned in
	// https://github.com/michaelklishin/rabbit-hole/blob/1de83b96b8ba1e29afd003143a9d8a8234d4e913/client.go#L153
	if err.Error() == "Error: API responded with a 401 Unauthorized" {
		// Only one node in a multi node RabbitMQ cluster will update the password.
		// All other nodes are expected to run into this branch.
		u.Log.V(1).Info("HTTP request with old password returned 401 Unauthorized; authenticating with new password...",
			"method", httpMethod, "path", pathUsers)
		client.SetPassword(newPasswd)
		return u.authenticate(client)
	}
	u.Log.Error(err, "HTTP request failed", "method", httpMethod, "path", pathUsers)
	return err
}

// authenticate checks whether authentication succeeds.
// It queries /api/whoami (although it could query any other endpoint requiring basic auth).
// Returns an error if authentication fails.
func (u *PasswordUpdater) authenticate(client RabbitClient) error {
	const pathWhoAmI = "/api/whoami"
	_, err := client.Whoami()
	if err != nil {
		u.Log.Error(
			err,
			fmt.Sprintf("failed to GET %s with new password", pathWhoAmI),
			"user",
			client.GetUsername(),
		)
		return err
	}
	u.Log.V(2).Info(
		fmt.Sprintf(
			"GET %s with new password succeeded, therefore skipping PUT %s...",
			pathWhoAmI,
			"/api/users/"+client.GetUsername(),
		),
	)
	return nil
}

// updateAdminFile writes the admin credentials into the rabbitmqadmin file using gopkg.in/ini.v1.
// If the file does not exist, it creates a new one.
func (u *PasswordUpdater) updateAdminFile(cred UserCredentials) error {
	cfg, err := ini.LooseLoad(u.AdminFile)
	if err != nil {
		return fmt.Errorf("failed to load admin ini file: %w", err)
	}
	// Update the default section with the new admin username and password.
	cfg.Section(adminFileSection).Key("username").SetValue(cred.Username)
	cfg.Section(adminFileSection).Key("password").SetValue(cred.Password)
	if err := cfg.SaveTo(u.AdminFile); err != nil {
		return fmt.Errorf("failed to save admin ini file: %w", err)
	}
	return nil
}

// checkAdminFile checks whether the admin credentials file contains the expected username and password.
// Returns true if the file is correct, or false if it is missing or has incorrect credentials.
func (u *PasswordUpdater) checkAdminFile(cred UserCredentials) (bool, error) {
	cfg, err := ini.LooseLoad(u.AdminFile)
	if err != nil {
		return false, err
	}
	section := cfg.Section(adminFileSection)
	if strings.TrimSpace(section.Key("username").String()) != cred.Username ||
		strings.TrimSpace(section.Key("password").String()) != cred.Password {
		return false, nil
	}
	return true, nil
}
