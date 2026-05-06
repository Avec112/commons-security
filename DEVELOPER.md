# Development

## Release how to!

### Files needed
See `jreleaser.yml`

Create `~/.jreleaser/config.properties`

```properties
# --- GitHub access ---
JRELEASER_GITHUB_TOKEN=<github-token>

# --- GPG ---
JRELEASER_GPG_PASSPHRASE=<passphrase>

# --- Maven Central ---
JRELEASER_MAVENCENTRAL_USERNAME=<username>
JRELEASER_MAVENCENTRAL_PASSWORD=<>

# Optional defaults (handy if you have multiple projects)
JRELEASER_DEFAULT_REPO_OWNER=Avec112
JRELEASER_DEFAULT_REPO_NAME=commons-security
```




### Release steps
```bash
mvn clean verify

mvn versions:set -DnewVersion=0.9.0

git add .
git commit -m "Release 0.9.0"
git push

mvn clean deploy -DaltDeploymentRepository=local::default::file://$(pwd)/target/staging-deploy
mvn -N jreleaser:full-release -Djreleaser.dry.run=true
mvn -N jreleaser:full-release

# Verify publishing https://central.sonatype.com/ 

# Update version after successful release
mvn versions:set -DnewVersion=0.9.1-SNAPSHOT
git add .
git commit -m "Next development iteration 0.9.1-SNAPSHOT"
git push
```