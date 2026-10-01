package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wneessen/go-mail"
)

// MailMessage is one outbound notification. The SMTP client library builds MIME.
type MailMessage struct {
	From    string
	To      []string
	Subject string
	Text    string
	HTML    string
}

// MailSender sends one composed message. Tests swap in a recorder.
type MailSender interface {
	Send(ctx context.Context, msg MailMessage) error
}

// SMTPConfig is environment-driven mail settings. Host empty disables the feature.
type SMTPConfig struct {
	Host           string
	Port           int
	Username       string
	Password       string
	PasswordFile   string
	From           string
	To             []string
	UseSTARTTLS    bool
	UseImplicitTLS bool
}

// SMTPConfigFromEnv reads SMTP_* variables. Unset host means disabled.
// A set host with missing From is also treated as disabled (no startup failure).
// SMTP_TO is optional: it is the fallback recipient list when a policy has none.
func SMTPConfigFromEnv() (SMTPConfig, error) {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	if host == "" {
		return SMTPConfig{}, nil
	}
	port := 587
	if raw := strings.TrimSpace(os.Getenv("SMTP_PORT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 65535 {
			return SMTPConfig{}, fmt.Errorf("SMTP_PORT must be 1–65535")
		}
		port = n
	}
	to := splitMailList(os.Getenv("SMTP_TO"))
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	useStartTLS := os.Getenv("SMTP_STARTTLS") != "false"
	implicit := os.Getenv("SMTP_TLS") == "true"
	if implicit {
		useStartTLS = false
	}
	return SMTPConfig{
		Host:           host,
		Port:           port,
		Username:       os.Getenv("SMTP_USERNAME"),
		Password:       os.Getenv("SMTP_PASSWORD"),
		PasswordFile:   os.Getenv("SMTP_PASSWORD_FILE"),
		From:           from,
		To:             to,
		UseSTARTTLS:    useStartTLS,
		UseImplicitTLS: implicit,
	}, nil
}

func splitMailList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// smtpSender delivers mail through github.com/wneessen/go-mail.
type smtpSender struct {
	cfg SMTPConfig
}

// NewSMTPSender builds a MailSender. Empty Host returns (nil, nil).
func NewSMTPSender(cfg SMTPConfig) (MailSender, error) {
	if cfg.Host == "" {
		return nil, nil
	}
	if cfg.From == "" {
		return nil, errors.New("smtp: from is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	return &smtpSender{cfg: cfg}, nil
}

func (s *smtpSender) Send(ctx context.Context, msg MailMessage) error {
	if len(msg.To) == 0 {
		return errors.New("smtp: at least one recipient is required")
	}
	password, err := s.password()
	if err != nil {
		return err
	}
	m := mail.NewMsg()
	if err := m.From(msg.From); err != nil {
		return fmt.Errorf("smtp from: %w", err)
	}
	if err := m.To(msg.To...); err != nil {
		return fmt.Errorf("smtp to: %w", err)
	}
	m.Subject(msg.Subject)
	m.SetBodyString(mail.TypeTextPlain, msg.Text)
	if msg.HTML != "" {
		m.AddAlternativeString(mail.TypeTextHTML, msg.HTML)
	}

	opts := []mail.Option{
		mail.WithPort(s.cfg.Port),
		mail.WithTimeout(20 * time.Second),
	}
	if s.cfg.UseImplicitTLS {
		opts = append(opts, mail.WithSSL())
	} else if s.cfg.UseSTARTTLS {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	} else {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSOpportunistic))
	}
	if s.cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(password),
		)
	}
	client, err := mail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.DialAndSendWithContext(ctx, m); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

func (s *smtpSender) password() (string, error) {
	if s.cfg.PasswordFile != "" {
		b, err := os.ReadFile(s.cfg.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("read SMTP_PASSWORD_FILE: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return s.cfg.Password, nil
}
