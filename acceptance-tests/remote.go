package acceptance_tests

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"golang.org/x/crypto/ssh"
)

// runOnRemote runs cmd on a remote machine using SSH.
func runOnRemote(user string, addr string, privateKey string, cmd string) (string, string, error) {
	client, err := buildSSHClient(user, addr, privateKey)
	if err != nil {
		return "", "", err
	}

	session, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer session.Close()

	var stdOutBuffer bytes.Buffer
	var stdErrBuffer bytes.Buffer
	session.Stdout = &stdOutBuffer
	session.Stderr = &stdErrBuffer
	err = session.Run(cmd)
	return stdOutBuffer.String(), stdErrBuffer.String(), err
}

// copyFileFromRemote copies a remote file from remotePath on host addr to localFile with permissions via SSH. localFile
// must exist and be writable.
func copyFileFromRemote(user string, addr string, privateKey string, remotePath string, localFile *os.File, permissions os.FileMode) error {
	clientConfig, err := buildSSHClientConfig(user, privateKey)
	if err != nil {
		return err
	}

	scpClient := scp.NewClient(fmt.Sprintf("%s:22", addr), clientConfig)
	if err := scpClient.Connect(); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	err = localFile.Chmod(permissions)

	if err != nil {
		return err
	}

	err = scpClient.CopyFromRemote(context.Background(), localFile, remotePath)

	if err != nil {
		return err
	}

	return localFile.Sync()
}

// buildSSHClientConfig creates a new SSH config to use with the ssh package.
func buildSSHClientConfig(user string, privateKey string) (*ssh.ClientConfig, error) {
	key, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            user,
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}, nil
}

// buildSSHClient creates a new SSH client that is connected to the host addr.
func buildSSHClient(user string, addr string, privateKey string) (*ssh.Client, error) {
	config, err := buildSSHClientConfig(user, privateKey)
	if err != nil {
		return nil, err
	}

	writeLog(fmt.Sprintf("Connecting to %s:%d as user %s using private key\n", addr, 22, user))
	return ssh.Dial("tcp", net.JoinHostPort(addr, "22"), config)
}
