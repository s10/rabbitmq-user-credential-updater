package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
)

// NewPasswordUpdater creates a new instance of PasswordUpdater with a properly
// initialized CredentialCache and file system watcher.
func NewPasswordUpdater(adminFile string, watchDir string, done chan<- bool, log logr.Logger, adminClient RabbitClient, authClient RabbitClient) (*PasswordUpdater, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	log.V(1).Info("start watching", "directory", watchDir)
	if err := watcher.Add(watchDir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to add directory %q to watcher: %w", watchDir, err)
	}

	credentialState := initCredentialCache(watchDir, log)
	credentialSpec := make(map[string]UserCredentials)

	return &PasswordUpdater{
		AdminFile:       adminFile,
		WatchDir:        watchDir,
		Watcher:         watcher,
		Done:            done,
		Log:             log,
		adminClient:     adminClient,
		authClient:      authClient,
		CredentialState: credentialState,
		CredentialSpec:  credentialSpec,
	}, nil
}

// initCredentialCache scans the watch directory and loads existing credential files
// into a map keyed by userID.
func initCredentialCache(watchDir string, log logr.Logger) map[string]UserCredentials {
	credentialCache := make(map[string]UserCredentials)
	files, err := filepath.Glob(filepath.Join(watchDir, userFilePrefix+"*"))
	if err != nil {
		log.Error(err, "failed to glob watch directory", "watchDir", watchDir)
		return credentialCache
	}

	for _, f := range files {
		name := filepath.Base(f)
		parts := strings.SplitN(name[len(userFilePrefix):], "_", 2)
		if len(parts) != 2 {
			log.V(2).Info("ignoring file with unexpected name format", "file", name)
			continue
		}
		userID, key := parts[0], parts[1]
		content, err := os.ReadFile(f)
		if err != nil {
			log.Error(err, "failed to read credential file", "file", name)
			continue
		}
		val := strings.TrimSpace(string(content))
		cred := credentialCache[userID]
		switch key {
		case "username":
			cred.Username = val
		case "password":
			cred.Password = val
		case "tag":
			cred.Tag = val
		}
		credentialCache[userID] = cred
	}

	return credentialCache
}
