// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package scram

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// CheckVectors runs every case of drivers/conformance/scram/vectors.yaml (README §7
// "checkScramVectors"): SASLprep cases, full exchanges, and rejection of a forged serverFinal.
// It returns the first failure, naming the case.
func CheckVectors(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		SASLPrep []struct {
			Name   string `yaml:"name"`
			Input  string `yaml:"input"`
			Output string `yaml:"output"`
			Error  bool   `yaml:"error"`
		} `yaml:"saslprep"`
		Exchanges []struct {
			Name        string `yaml:"name"`
			User        string `yaml:"user"`
			Password    string `yaml:"password"`
			ClientNonce string `yaml:"clientNonce"`
			ClientFirst string `yaml:"clientFirst"`
			ServerFirst string `yaml:"serverFirst"`
			ClientFinal string `yaml:"clientFinal"`
			ServerFinal string `yaml:"serverFinal"`
		} `yaml:"exchanges"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("scram vectors: %w", err)
	}
	if len(doc.SASLPrep) == 0 || len(doc.Exchanges) == 0 {
		return fmt.Errorf("scram vectors: no cases in %s", path)
	}
	for _, v := range doc.SASLPrep {
		got, err := SASLPrep(v.Input)
		switch {
		case v.Error && err == nil:
			return fmt.Errorf("saslprep/%s: expected a refusal, got %q", v.Name, got)
		case !v.Error && err != nil:
			return fmt.Errorf("saslprep/%s: refused: %v", v.Name, err)
		case !v.Error && got != v.Output:
			return fmt.Errorf("saslprep/%s: got %q, want %q", v.Name, got, v.Output)
		}
	}
	for _, v := range doc.Exchanges {
		c, err := NewClientWithNonce(v.User, v.Password, v.ClientNonce)
		if err != nil {
			return fmt.Errorf("exchange/%s: %v", v.Name, err)
		}
		if got := c.ClientFirst(); got != v.ClientFirst {
			return fmt.Errorf("exchange/%s: clientFirst %q, want %q", v.Name, got, v.ClientFirst)
		}
		final, err := c.ProcessServerFirst(v.ServerFirst)
		if err != nil {
			return fmt.Errorf("exchange/%s: serverFirst: %v", v.Name, err)
		}
		if final != v.ClientFinal {
			return fmt.Errorf("exchange/%s: clientFinal %q, want %q", v.Name, final, v.ClientFinal)
		}
		if err := c.VerifyServerFinal(v.ServerFinal); err != nil {
			return fmt.Errorf("exchange/%s: serverFinal: %v", v.Name, err)
		}
		if len(v.ServerFinal) < 3 {
			return fmt.Errorf("exchange/%s: serverFinal too short to forge", v.Name)
		}
		// Same forgery as the .NET check: change the first signature character.
		changed := "A"
		if v.ServerFinal[2] == 'A' {
			changed = "B"
		}
		forged := v.ServerFinal[:2] + changed + v.ServerFinal[3:]
		again, _ := NewClientWithNonce(v.User, v.Password, v.ClientNonce)
		if _, err := again.ProcessServerFirst(v.ServerFirst); err != nil {
			return fmt.Errorf("exchange/%s: serverFirst (forgery run): %v", v.Name, err)
		}
		if again.VerifyServerFinal(forged) == nil {
			return fmt.Errorf("exchange/%s: forged serverFinal accepted", v.Name)
		}
	}
	return nil
}
