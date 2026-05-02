// Package smtp sends mail using the configured SMTP server.
// Supports plain (none), STARTTLS, and implicit TLS modes.
package smtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
)

type Mailer struct {
	cfg settings.SMTP
}

func New(cfg settings.SMTP) *Mailer { return &Mailer{cfg: cfg} }

func (m *Mailer) Enabled() bool { return m.cfg.Enabled && m.cfg.Host != "" }

func (m *Mailer) Send(to, subject, body string) error {
	if !m.Enabled() {
		return errors.New("smtp not configured")
	}
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	from := m.cfg.From
	if from == "" {
		from = m.cfg.Username
	}
	msg := []byte("From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		body + "\r\n")

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var c *smtp.Client
	switch strings.ToLower(m.cfg.TLS) {
	case "tls":
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}
		c, err = smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			return err
		}
	default: // none or starttls
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		c, err = smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			return err
		}
		if strings.EqualFold(m.cfg.TLS, "starttls") {
			if err := c.StartTLS(&tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}
	defer c.Quit()

	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return err
	}
	return wc.Close()
}
