package acceptance_tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
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

// copyFileToRemote copies a local file from fileReader to remotePath at the host addr with permissions via SSH.
func copyFileToRemote(user string, addr string, privateKey string, remotePath string, fileReader io.Reader, permissions string) error {
	clientConfig, err := buildSSHClientConfig(user, privateKey)
	if err != nil {
		return err
	}

	scpClient := scp.NewClient(fmt.Sprintf("%s:22", addr), clientConfig)
	if err := scpClient.Connect(); err != nil {
		return err
	}

	return scpClient.CopyFile(context.Background(), fileReader, remotePath, permissions)
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

// startSSHPortForwarder forwards a TCP connection from a given port on the local machine to a given port on the remote machine
// Starts in background, cancel via context
func startSSHPortForwarder(user string, addr string, privateKey string, localPort, remotePort int, ctx context.Context) error {
	remoteConn, err := buildSSHClient(user, addr, privateKey)
	if err != nil {
		return err
	}

	writeLog(fmt.Sprintf("Listening on 127.0.0.1:%d on local machine\n", remotePort))
	localListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return err
	}

	go func() {
		for {
			localClient, err := localListener.Accept()
			if err != nil {
				if err == io.EOF {
					writeLog("Local connection closed")
				} else {
					writeLog(fmt.Sprintf("Error accepting connection on local listener: %s\n", err.Error()))
				}

				return
			}

			remoteConn, err := remoteConn.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
			if err != nil {
				writeLog(fmt.Sprintf("Error dialing local port %d: %s\n", remotePort, err.Error()))
				return
			}

			// From https://sosedoff.com/2015/05/25/ssh-port-forwarding-with-go.html
			copyConnections(localClient, remoteConn)
		}
	}()

	go func() {
		<-ctx.Done()
		writeLog("Closing local listener")
		localListener.Close()
	}()

	return nil
}

// startReverseSSHPortForwarder forwards a TCP connection from a given port on the remote machine to a given port on the local machine
// Starts in background, cancel via context
func startReverseSSHPortForwarder(user string, addr string, privateKey string, remotePort, localPort int, ctx context.Context) error {
	remoteConn, err := buildSSHClient(user, addr, privateKey)
	if err != nil {
		return err
	}

	writeLog(fmt.Sprintf("Listening on 127.0.0.1:%d on remote machine\n", remotePort))
	remoteListener, err := remoteConn.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
	if err != nil {
		return err
	}

	go func() {
		for {
			remoteClient, err := remoteListener.Accept()
			if err != nil {
				if err == io.EOF {
					writeLog("Remote connection closed")
				} else {
					writeLog(fmt.Sprintf("Error accepting connection on remote listener: %s\n", err.Error()))
				}

				return
			}

			localConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
			if err != nil {
				writeLog(fmt.Sprintf("Error dialing local port %d: %s\n", localPort, err.Error()))
				return
			}

			// From https://sosedoff.com/2015/05/25/ssh-port-forwarding-with-go.html
			copyConnections(remoteClient, localConn)
		}
	}()

	go func() {
		<-ctx.Done()
		writeLog("Closing remote listener")
		remoteListener.Close()
	}()

	return nil
}

// copyConnections copies data between two connections. The function blocks until both client and remote are done.
func copyConnections(client net.Conn, remote net.Conn) {
	chDone := make(chan bool)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(client, remote) // blocks until EOF
		if err != nil {
			log.Println("error while copy remote->local:", err)
		}
		chDone <- true
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, client) // blocks until EOF
		if err != nil {
			log.Println("error while copy local->remote:", err)
		}
		chDone <- true
	}()

	<-chDone
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

// checkListening checks if a tcp port is open at addr.
func checkListening(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return err
	}
	if conn != nil {
		defer conn.Close()
	}

	return nil
}
