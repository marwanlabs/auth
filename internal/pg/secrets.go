package pg

import (
	"errors"
	"strings"
)

// scrub removes the connection string and any known password material from a
// message so credentials never reach logs or operator-facing errors. It is
// applied to every error this package returns, as a defense-in-depth layer on
// top of the driver's own redaction.
func scrub(dsn, password, s string) string {
	if dsn != "" {
		s = strings.ReplaceAll(s, dsn, "[redacted]")
	}
	if password != "" {
		s = strings.ReplaceAll(s, password, "[redacted]")
	}
	return s
}

// redactError returns err as a plain error whose text carries neither the
// connection string nor its password.
func redactError(c *Config, err error) error {
	if err == nil {
		return nil
	}
	if c == nil {
		return err
	}
	return errors.New(scrub(c.dsn, c.password, err.Error()))
}
