// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors
// Regenerates src/generated/ from <repo>/proto with buf + protoc-gen-es (PD-161).
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
execSync('npx buf generate ../../proto --template buf.gen.yaml', { cwd: root, stdio: 'inherit' });
