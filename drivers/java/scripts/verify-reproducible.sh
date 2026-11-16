#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# TC-DRV-JAVA-028 (java-driver.md §1): two clean builds with -Preproducible, without the build
# cache, must produce byte-identical jars (driver, processor: main, sources, javadoc). Each
# build runs at a different time, so any timestamp, build path or nondeterministic order in an
# archive shows up as a difference. Usage: drivers/java/scripts/verify-reproducible.sh
set -euo pipefail
cd "$(dirname "$0")/.."

out=build/reproducible
rm -rf "$out"
for run in 1 2; do
  ./gradlew --no-build-cache --console=plain -q -Preproducible \
    clean :driver:jar :driver:sourcesJar :driver:javadocJar \
    :processor:jar :processor:sourcesJar :processor:javadocJar
  mkdir -p "$out/$run"
  cp driver/build/libs/*.jar processor/build/libs/*.jar "$out/$run/"
  (cd "$out/$run" && sha256sum -- *.jar) > "$out/$run.sha256"
done

cat "$out/1.sha256"
if ! diff "$out/1.sha256" "$out/2.sha256"; then
  echo "TC-DRV-JAVA-028 FAILED: the two builds differ (jars kept in $out/1 and $out/2)" >&2
  exit 1
fi
echo "TC-DRV-JAVA-028 OK: $(wc -l < "$out/1.sha256") jars byte-identical across two clean builds"
