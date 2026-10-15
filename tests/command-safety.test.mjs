import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { evaluateLocalCommand, executableCommandText } from '../extensions/command-safety.ts';

// All command fixtures below are DATA. No subprocesses, devices, databases, gate,
// Git repositories, or services are invoked by this suite.
const cwd = '/workspace/project';
const findings = command => evaluateLocalCommand(command, cwd);
const mandatory = command => findings(command).filter(f => f.enforcement !== 'context');
function expectRule(command, ruleId, enforcement = 'human-required', evaluate = evaluateLocalCommand) {
  const actual = evaluate(command, cwd);
  assert.ok(actual.some(f => f.ruleId === ruleId && f.enforcement === enforcement), `${command}: expected ${enforcement} ${ruleId}; got ${JSON.stringify(actual)}`);
}
function noMandatory(command) {
  assert.deepEqual(mandatory(command), [], command);
}

// Oracle: coverage plan §§2–3 supplies review/protected-target policy.
// Independent semantics checked via curl of official docs during implementation:
// https://git-scm.com/docs/git-clean: -n/--dry-run "Don't actually remove anything".
// https://git-scm.com/docs/git-push: '+' "does the same thing as --force";
// <src> without :<dst> updates same ref UNLESS remote.<repository>.push maps it.
// This last exception falsifies treating a lone feature source as a proven target.
// --repo docs: a positional repository takes precedence; independently confirmed
// https://raw.githubusercontent.com/git/git/master/builtin/push.c:
// "if (argc > 0) repo = argv[0]". --force-if-includes alone is a documented no-op.
// https://man7.org/linux/man-pages/man1/rsync.1.html: --dry-run/-n "trial run
// with no changes made"; --del aliases --delete-during, -e takes a remote shell.
// https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html: --dryrun displays
// operations "without actually running them" (NOT a universal --dry-run flag).
// https://cloud.google.com/sdk/gcloud/reference/storage/rsync: documented
// --delete-unmatched-destination-objects and --dry-run spelling.
// https://docs.docker.com/reference/cli/docker/compose/down/: -v/--volumes
// removes named volumes and anonymous volumes attached to containers.
// https://man7.org/linux/man-pages/man1/truncate.1.html: '+' extends by, '-'
// reduces by, '<' at most, '>' at least; absolute size can shrink an existing file.
// https://www.postgresql.org/docs/current/sql-delete.html: "If the WHERE clause
// is absent, the effect is to delete all rows in the table."
// https://redis.io/docs/latest/develop/tools/cli/: -n selects DB, -u URI, and
// --quoted-input is a BOOLEAN "Force input to be handled as quoted strings".
// Falsifiers: raw text matching, dry-run operands treated as flags, chain-wide
// exemptions, source/destination confusion, loss of earlier repeated SQL options.

for (const command of [
  'git stash drop', 'git stash drop stash@{2}', 'git stash clear',
  '/usr/bin/git -C "a b" stash clear', 'rtk git stash drop',
  'rtk proxy git --no-pager stash clear', 'env MODE=test git stash clear',
  'sudo -u user git stash clear', 'command git stash clear',
  'timeout -k 2s 10s git stash clear', 'nice -n 5 nohup git stash clear',
  'git -c color.ui=false --git-dir=.git --work-tree=. stash clear',
  'git --namespace ns --config-env color.ui=COLOR stash drop',
  'git -Csubdir -ccolor.ui=false stash clear',
]) test(`stash destruction: ${command}`, () => expectRule(command, 'git.stash-destruction'));

for (const command of [
  'git stash list', 'git stash list --oneline', 'git stash show',
  'git stash push -m "drop clear"', 'git stash -m drop',
  'git commit -m "git stash clear; git reset --hard; rm -rf /"',
  'git log --grep="git stash clear"', 'grep "git stash clear" README.md',
  'echo "git stash drop"', 'git --version',
]) test(`stash safe neighbor: ${command}`, () => noMandatory(command));

for (const command of [
  'git checkout -- file.ts', 'git checkout -- --', 'git checkout -- file.ts --', 'git checkout -- .', 'git checkout HEAD -- "path with spaces"',
  'git checkout branch -- :/', 'git restore one.ts', 'git restore .',
  'git restore --source=HEAD -- "a b"', 'git restore --staged --worktree .',
  'git restore -SW .', 'git restore -sHEAD .',
]) test(`working-file discard: ${command}`, () => expectRule(command, 'git.working-tree-discard'));
for (const command of ['git restore --staged .', 'git restore -S one.ts', 'git restore --staged --source=HEAD one.ts', 'git checkout feature', 'git switch feature']) {
  test(`index/branch safe neighbor: ${command}`, () => noMandatory(command));
}
for (const command of ['git reset --hard', 'git reset HEAD --hard', 'git --no-pager reset --hard HEAD']) {
  test(`hard reset: ${command}`, () => expectRule(command, 'git.reset-hard'));
}
for (const command of ['git reset --soft HEAD~1', 'git reset HEAD one.ts', 'git reset --mixed']) test(`reset neighbor: ${command}`, () => noMandatory(command));
for (const command of ['git clean -f', 'git clean -dfx', 'git clean --force -d', 'git clean -ff .']) test(`forced clean: ${command}`, () => expectRule(command, 'git.clean'));
for (const command of ['git clean -n', 'git clean -dn', 'git clean -nd', 'git clean -dfn', 'git clean --force --dry-run', 'git clean -n -f', 'git clean -e "-f"']) test(`clean preview/operand: ${command}`, () => noMandatory(command));
test('clean exclude operand is not a dry run', () => expectRule('git clean -f -e -n', 'git.clean'));
test('flags after -- are operands', () => expectRule('git clean -f -- -n', 'git.clean'));
test('clean preview cannot exempt later destructive chain', () => expectRule('git clean -dfn && git clean -df', 'git.clean'));

for (const command of [
  'git push --force origin HEAD:main', 'git push origin HEAD:master -f',
  'git push --force-with-lease origin feature:refs/heads/production',
  'git push --force-with-lease=refs/heads/main:deadbeef origin HEAD:main',
  'git push origin +HEAD:refs/heads/prod', 'git push origin +feature:main',
  'git push origin +HEAD:feature +HEAD:refs/heads/main',
  'git push --repo other origin +HEAD:main', 'git push -u -f origin HEAD:main',
  'env --split-string="git push origin +HEAD:main"',
  'env -S"git push origin +HEAD:main"',
  '/usr/bin/git -C repo push --force origin HEAD:main',
  'rtk git push origin +HEAD:main', 'git push -f origin main',
]) test(`protected destination: ${command}`, () => expectRule(command, 'git.force-push-protected', 'hard-block'));
for (const command of [
  'git push --force-with-lease', 'git push -f origin', 'git push --mirror origin',
  'git push --force --all origin', 'git push -f origin HEAD',
  'git push origin +HEAD', 'git push -f origin feature',
  'git push -f origin HEAD:$BRANCH', 'git push origin "+HEAD:${DEST}"',
  'git push -f origin HEAD:refs/heads/*', 'git push -f origin :',
  'git push --force --tags origin', 'git push origin +HEAD:',
  'git push --repo=origin --force HEAD:feature',
]) test(`unresolved force destination: ${command}`, () => expectRule(command, 'git.force-push-unresolved', 'hard-block'));
for (const command of [
  'git push -f origin HEAD:feature', 'git push origin +HEAD:refs/heads/feature',
  'git push --force-with-lease origin main:feature',
  'git push --repo=other --force origin HEAD:feature',
  'git push origin HEAD:main +HEAD:feature', // Only '+' refspec is forced.
  'git push -f origin HEAD:refs/tags/main',
]) test(`explicit feature force: ${command}`, () => {
  noMandatory(command);
  expectRule(command, 'git.force-push', 'context');
});
for (const command of ['git push origin main', 'git push origin feature:main', 'git push --delete origin feature', 'git push --repo origin +HEAD:main', 'git push --force-if-includes origin main', 'git push --force --no-force origin main', 'git push --force-with-lease --no-force-with-lease origin main', 'echo "git push --force origin main"']) test(`push neighbor: ${command}`, () => noMandatory(command));

test('strictest findings survive safe segments and pipe boundaries', () => {
  const command = 'git status; git push origin +HEAD:main && git stash clear || git restore . | echo done';
  expectRule(command, 'git.force-push-protected', 'hard-block');
  expectRule(command, 'git.stash-destruction');
  expectRule(command, 'git.working-tree-discard');
});

for (const command of ['rm one.txt', 'rm -f "/tmp/unrelated state"', 'unlink src.ts', 'rm -rf ./build', 'git rm one.ts', 'shred file', 'find . -delete']) test(`file deletion: ${command}`, () => expectRule(command, 'file.delete'));
for (const command of ['rm -rf /', 'rm -rf /etc', 'rm -r ../../etc', 'rm -rf "$HOME"', 'rm -rf "$TARGET"', 'rm -rf /Users/user']) test(`catastrophic deletion: ${command}`, () => expectRule(command, 'file.catastrophic-delete', 'hard-block'));
for (const command of ['truncate -s 0 data', 'truncate --size=0 data', 'truncate -s -1K data', 'truncate -s 10 data', 'truncate -s \'<10\' data', 'truncate -r source data', 'truncate -s "$SIZE" data']) test(`truncate: ${command}`, () => expectRule(command, 'file.truncate'));
for (const command of ['truncate -s +10 data', 'truncate --help', 'dropdb --help', 'mkfs --help', 'ls src', 'git rm --cached one.ts', 'git rm -n one.ts', 'find . -name "rm -rf /"', 'printf "git reset --hard"']) test(`file safe neighbor: ${command}`, () => noMandatory(command));
for (const command of [': > data', '> data', 'printf "" > data', 'cat /dev/null > data']) test(`proven empty redirect: ${command}`, () => expectRule(command, 'file.truncate'));
for (const command of ['echo hello > /etc/config', ': > "$TARGET"']) test(`protected redirect: ${command}`, () => expectRule(command, 'file.protected-truncate'));
test('raw-device redirection', () => expectRule('echo x > /dev/sda', 'disk.destroy', 'hard-block'));
test('literal directory changes retain target context', () => expectRule('cd /; rm -rf etc', 'file.catastrophic-delete', 'hard-block'));
test('redirection descriptors are not whitespace-separated numeric arguments', () => {
  expectRule('git push -f origin HEAD:feature 2 >log', 'git.force-push-unresolved', 'hard-block');
  expectRule('git push -f origin HEAD:feature 2>log', 'git.force-push', 'context');
  expectRule('git push -f origin HEAD:feature "2">log', 'git.force-push-unresolved', 'hard-block');
});
for (const command of ['echo hello > result.txt', 'echo hello >> result.txt', 'echo hi > /dev/null']) test(`ordinary output: ${command}`, () => noMandatory(command));

for (const command of [
  'rsync -a --delete src/ dst/', 'rsync --delete-before src/ dst/',
  'rsync --delete-excluded src/ dst/', 'rsync --del src/ dst/',
  'rsync --remove-source-files src/ dst/',
  'rsync --delete --exclude -n src/ dst/', 'rsync --delete src/ dst/ --dryrun',
  'aws --profile testing s3 sync src s3://bucket --delete',
  'aws s3 sync src s3://bucket --delete --exclude --dryrun',
  'aws s3 sync src s3://bucket --delete --dry-run',
  'gsutil -m rsync -rd src gs://bucket',
  'gcloud --project sandbox storage rsync src gs://bucket --delete-unmatched-destination-objects',
]) test(`deletion sync: ${command}`, () => {
  expectRule(command, 'sync.delete');
  assert.equal(findings(command).find(f => f.ruleId === 'sync.delete').risk, 'critical');
});
for (const command of [
  'rsync -an --delete src/ dst/', 'rsync --delete --dry-run src/ dst/',
  'rsync --exclude=--delete src/ dst/', 'rsync -a src/ dst/',
  'aws s3 sync src s3://bucket --delete --dryrun', 'aws s3 sync src s3://bucket',
  'gsutil rsync -nd src gs://bucket',
  'gcloud storage rsync src gs://bucket --delete-unmatched-destination-objects --dry-run',
]) test(`sync neighbor: ${command}`, () => noMandatory(command));
test('sync dry run is invocation scoped', () => expectRule('rsync -an --delete src dst; rsync -a --delete src dst', 'sync.delete'));
test('real preview flags after -- are operands', () => {
  expectRule('rsync --delete -- src dst --dry-run', 'sync.delete');
  expectRule('aws s3 sync --delete -- src s3://bucket --dryrun', 'sync.delete');
});

for (const command of [
  'redis-cli FLUSHALL', 'redis-cli -h shared -n 2 flushdb ASYNC',
  'redis-cli --quoted-input FLUSHALL', 'redis-cli -s /tmp/redis.sock FLUSHDB',
  'redis-cli --tls --cacert cert.pem FLUSHALL',
  'redis-cli --user test --pass FLUSHALL FLUSHDB', 'dropdb test_db',
  'supabase db reset', 'supabase db reset --local', 'supabase --workdir test db reset',
  'psql -c "DROP TABLE users"', 'psql --command="TRUNCATE TABLE users"',
  'psql -c "/* cleanup */ DROP TABLE users"',
  'psql -c "DELETE FROM users -- WHERE ignored"',
  'psql -c "DELETE FROM users"', 'psql -c \'DELETE FROM "where"\'',
  'psql -c "DROP TABLE users" -c "SELECT 1"',
  'mysql -e "DROP DATABASE test"', 'mysql -psecret -e "DROP DATABASE test"',
  'mysql -p -e "DROP DATABASE test"', 'mysql --password -e "DROP DATABASE test"',
  'mariadb --execute="TRUNCATE t"',
  'sqlite3 state.db "DELETE FROM users; SELECT 1"',
  'mongosh --eval "db.dropDatabase()"', 'mongo --eval "db.dropCollection(\"users\")"',
  'mongosh --eval "db.users.drop()"', 'sqlcmd -Q "DROP TABLE users"',
  'bq query "TRUNCATE TABLE dataset.users"', 'snowsql -q "DROP SCHEMA test"',
]) test(`database destructive: ${command}`, () => expectRule(command, 'database.bulk-delete'));
for (const command of [
  'redis-cli GET FLUSHALL', 'redis-cli -h FLUSHDB GET key',
  'psql -c "SELECT 1"', 'psql -c "DELETE FROM users WHERE id=1"',
  'psql -c "SELECT \'DROP TABLE users\'"', 'psql -c "SELECT 1; -- DROP TABLE users"',
  'psql -f cleanup.sql', 'mysql -e "SELECT \'TRUNCATE users\'"',
  'sqlite3 state.db "SELECT 1"', 'mongosh --eval "db.users.find({})"',
  'mongosh --eval \'print("db.dropDatabase()")\'',
  'echo "DROP TABLE users"', 'grep "DELETE FROM users" schema.sql',
]) test(`database read/literal/file neighbor: ${command}`, () => noMandatory(command));
test('supported literal database pipelines distinguish data from execution', () => {
  for (const command of ['echo "DROP TABLE users" | psql', 'printf "%s" "TRUNCATE users" | mysql', 'echo FLUSHALL | redis-cli']) expectRule(command, 'database.bulk-delete');
  for (const command of ['echo "SELECT 1" | psql', 'echo "DROP TABLE users"; psql -c "SELECT 1"', 'echo "DROP TABLE users" | psql -c "SELECT 1"', 'echo FLUSHALL | redis-cli GET key']) noMandatory(command);
  expectRule('cat cleanup.sql | psql', 'shell.incomplete');
});
test('truncate aliases use the final size; reference sizes are not proof of growth', () => {
  expectRule('truncate -s +10 --size=0 data', 'file.truncate');
  noMandatory('truncate -s 0 --size=+10 data');
  expectRule('truncate --reference=small -s +10 data', 'file.truncate');
});
test('unsupported risky Git option abbreviations cannot claim safe', () => {
  expectRule('git reset --ha', 'shell.incomplete');
  expectRule('git push --fo origin HEAD:main', 'shell.incomplete');
});
test('SQL files and queries retain context, not claimed inspection', () => {
  expectRule('psql -f reset.sql', 'database.code', 'context');
  expectRule('psql -c "SELECT 1"', 'database.code', 'context');
});

for (const command of [
  'docker volume rm db', 'docker --context test volume prune', 'docker system prune',
  'podman volume rm db', 'podman system prune', 'podman container prune',
  'docker compose down -v', 'docker compose -f dev.yml down --volumes',
  'docker-compose -p local down -v', 'podman-compose down --volumes',
  'podman compose down -v', 'docker compose rm -v', 'docker rm -v db',
]) test(`container state removal: ${command}`, () => expectRule(command, 'container.persistent-delete'));
for (const command of ['docker volume ls', 'podman volume inspect db', 'docker compose down', 'docker-compose ps', 'podman system df', 'docker compose -f volumes.yml config']) test(`container neighbor: ${command}`, () => noMandatory(command));
for (const command of ['terraform state rm aws_instance.server', 'tofu -chdir=env state rm module.db']) test(`state removal: ${command}`, () => expectRule(command, 'infra.state-remove'));
for (const command of ['pulumi destroy', 'terraform destroy', 'kubectl -n test delete pods --all', 'helm uninstall app', 'aws ec2 terminate-instances --instance-ids test', 'gcloud compute instances delete test', 'az group delete --name test']) test(`infrastructure mutation: ${command}`, () => assert.ok(mandatory(command).some(f => f.risk === 'critical'), command));
for (const command of ['terraform state list', 'terraform plan', 'tofu show', 'pulumi stack ls', 'kubectl get pods', 'kubectl get pod delete', 'terraform state show destroy', 'helm status uninstall', 'aws s3 ls', 'aws ec2 describe-tags delete-tag', 'gcloud compute instances list', 'gcloud compute instances describe delete', 'az group show delete', 'helm list']) test(`infrastructure neighbor: ${command}`, () => noMandatory(command));

for (const command of [
  'mdadm --zero-superblock /dev/sdb', 'mdadm --create /dev/md0 --raid-devices=2 /dev/sdb /dev/sdc',
  'pvremove /dev/sdb', 'lvreduce -L 1G /dev/vg/data', 'lvremove /dev/vg/data',
  'dmsetup remove /dev/mapper/db', 'dd if=/dev/zero of=/dev/sdb',
  'mkfs.ext4 /dev/sdb', 'wipefs --all /dev/sdb', 'diskutil eraseDisk APFS data /dev/disk2',
]) test(`raw disk destruction: ${command}`, () => expectRule(command, 'disk.destroy', 'hard-block'));
for (const command of ['vgremove production', 'dmsetup remove db', 'mdadm --zero-superblock "$DEVICE"', 'lvreduce -L 1G "$LV"', 'wipefs -a "$DEVICE"']) test(`unresolved disk operation: ${command}`, () => expectRule(command, 'disk.unresolved-destruction'));
for (const command of ['mdadm --detail /dev/md0', 'dmsetup info db', 'wipefs /dev/sdb', 'fdisk -l /dev/sdb', 'parted /dev/sdb print', 'dd if=/dev/sda of=/dev/null', 'diskutil list', 'lsblk']) test(`disk inspection: ${command}`, () => noMandatory(command));

for (const command of [
  'echo "$(git stash clear)"', 'printf "%s" "$(git reset --hard)"',
  'grep "`git stash drop`" README', 'git commit -m "$(git stash clear)"',
  'bash -lc "git restore ."', 'sh -c \'git stash clear; echo done\'',
]) test(`real embedded shell execution: ${command}`, () => assert.ok(mandatory(command).length, command));
test('nested force push retains hard block', () => expectRule('bash -c \'git push origin +HEAD:main\'', 'git.force-push-protected', 'hard-block'));
test('nested and escaped command substitutions', () => {
  expectRule('echo "$(echo \\"$(git stash clear)\\")"', 'git.stash-destruction');
  expectRule('echo "${NAME:-$(git stash clear)}"', 'git.stash-destruction');
});
for (const command of [
  'echo \'$(git stash clear)\'', 'echo \'`git stash clear`\'',
  'echo \'$((target))\'', 'echo \'${target@P}\'',
  'echo "\\$(git stash clear)"', 'echo "git reset --hard; rm -rf /"',
]) test(`literal shell syntax: ${command}`, () => noMandatory(command));
for (const command of [
  'git "$ACTION" .', '$TOOL restore .', 'git stash "$ACTION"',
  'git alias-cleanup', 'bash -c "$BODY"', 'bash script.sh', './cleanup.sh',
  'if true; then git status; fi', 'git restore "unterminated',
  'eval "git reset --hard"', 'source cleanup.sh',
  'xargs rm', 'find . -exec rm {} \\;', 'echo "$((target))"',
  'cat <<EOF\ngit stash clear\nEOF', 'env -S "git stash clear"',
]) test(`incomplete shell requires human: ${command}`, () => assert.ok(mandatory(command).some(f => f.enforcement === 'human-required'), command));
for (const command of ['python -c "import shutil; shutil.rmtree(path)"', 'node -e "fs.rmSync(path)"', 'python cleanup.py']) test(`interpreter conservative review: ${command}`, () => expectRule(command, 'shell.interpreter'));
for (const command of ['node --version', 'python --version']) test(`interpreter inspection: ${command}`, () => noMandatory(command));

test('projection removes only literal harmless operands, preserves actual execution', () => {
  const destructive = /git\s+(?:stash\s+clear|reset\s+--hard)|rm\s+-rf/;
  for (const command of [
    'echo "git reset --hard; rm -rf /"',
    'grep "git stash clear" README', 'rg -e "rm -rf /" .',
    'git commit --message="git stash clear; rm -rf /"',
    'git log --grep="git reset --hard"',
  ]) assert.equal(destructive.test(executableCommandText(command)), false, command);
  for (const command of [
    'git reset --hard', 'echo "$(git stash clear)"',
    'git commit -m "$(git stash clear)"', 'bash -lc "rm -rf /"',
    'eval "git reset --hard"',
  ]) assert.equal(destructive.test(executableCommandText(command)), true, command);
});
test('comments are not executable, chains and quoting are preserved', () => {
  noMandatory('git status # git stash clear\necho okay');
  expectRule('git \\\n stash clear', 'git.stash-destruction');
  expectRule('echo "$(echo hi # )\ngit stash clear)"', 'git.stash-destruction');
  expectRule('echo "a; b"; git stash clear', 'git.stash-destruction');
  expectRule("git sta'sh' cl\"ea\"r", 'git.stash-destruction');
});
test('contract is pure, deterministic and produces only structured local findings', () => {
  const a = findings('git stash clear; git push origin +HEAD:main');
  assert.deepEqual(a, findings('git stash clear; git push origin +HEAD:main'));
  for (const f of a) {
    assert.deepEqual(Object.keys(f).sort(), ['enforcement', 'risk', 'ruleId', 'source', 'summary']);
    assert.equal(f.source, 'local');
    assert.equal(typeof f.summary, 'string');
    assert.ok(['hard-block', 'human-required', 'context'].includes(f.enforcement));
  }
});

// Review oracles (official upstream docs fetched independently for these fixes):
// git/Documentation/git-checkout.adoc: <tree-ish> [--] <pathspec> replaces files;
// -f throws away local changes; -B is -b plus branch reset, NOT a force checkout.
// git/Documentation/git-switch.adoc: --discard-changes/-f discard local changes.
// git/Documentation/git-push.adoc: named lease protects ONLY the named ref;
// git remote.c apply_cas + refs.c refname_match: abbreviated lease names match
// via the same refs/, refs/tags/, refs/heads/, refs/remotes/ expansion rules.
// git/Documentation/config/remote.adoc: .push defaults refspecs; .mirror enables
// --mirror. --config-env supplies configuration via environment, not literal RHS.
// RsyncProject/rsync/rsync.1.md's option summary documents the value options below.
// PostgreSQL sql-delete: WITH precedes DELETE, omitted WHERE deletes all rows.
// MongoDB db.collection.deleteMany/remove: {} selects all; remove justOne=true
// limits deletion to one. man7 wipefs(8): -n/--no-act omits write(2).
for (const command of [
  'git -c remote.origin.push=+HEAD:main push origin',
  'git -cremote.origin.push=+HEAD:feature push origin',
  'git -c remote.origin.mirror=true push origin',
  'git -c remote.origin.mirror push origin',
  'git --config-env=remote.origin.push=PUSH_SPEC push origin',
  'git --config-env remote.origin.mirror=MIRROR push origin',
  'git -c remote.origin.push="$PUSH" push origin',
]) test(`force-enabling Git config: ${command}`, () => expectRule(command, 'git.force-push-config', 'hard-block'));
for (const command of [
  'git -c core.editor=vim push origin HEAD:main',
  'git -c remote.origin.mirror=false push origin',
  'git -c remote.origin.push=HEAD:main push origin',
]) test(`non-forcing config neighbor: ${command}`, () => noMandatory(command));
test('safe configuration is not proof of an unknown alias', () => expectRule('git -c core.editor=vim cleanup', 'shell.incomplete'));
for (const command of [
  'git checkout HEAD file.ts', 'git checkout -f feature',
  'git checkout --force feature', 'git checkout -B feature -f',
  'git switch --discard-changes feature', 'git switch -f feature',
]) test(`additional work discard: ${command}`, () => expectRule(command, 'git.working-tree-discard'));
for (const command of ['git checkout feature', 'git checkout -b feature', 'git checkout -b feature HEAD', 'git checkout -B feature', 'git checkout -B feature HEAD', 'git switch -c feature']) {
  test(`non-forcing branch creation/reset: ${command}`, () => noMandatory(command));
}
for (const command of [
  'git push --force-with-lease=refs/heads/feature origin HEAD:main',
  'git push --force-with-lease=feature origin HEAD:main',
  'git push --force-with-lease=refs/heads/feature:deadbeef origin HEAD:main',
  'git push --force-with-lease=refs/heads/main origin HEAD:feature',
  'git push --force-if-includes origin HEAD:main',
]) test(`lease is destination-specific: ${command}`, () => noMandatory(command));
for (const command of [
  'git push --force-with-lease=refs/heads/main origin HEAD:main',
  'git push --force-with-lease=main origin HEAD:main',
  'git push --force-with-lease=heads/main origin HEAD:main',
  'git push --force-with-lease=refs/heads/feature origin +HEAD:main',
  'git push --force-with-lease=refs/heads/feature --force origin HEAD:main',
  'git push --force-with-lease=refs/heads/feature --force-with-lease=refs/heads/main origin HEAD:main',
]) test(`targeted protected force: ${command}`, () => expectRule(command, 'git.force-push-protected', 'hard-block'));
test('named lease without known refs remains unresolved', () => expectRule('git push --force-with-lease=refs/heads/feature origin', 'git.force-push-unresolved', 'hard-block'));
for (const option of ['--temp-dir', '-T', '--partial-dir', '--chmod', '--usermap', '--groupmap', '--bwlimit', '--chown', '--timeout', '--contimeout', '--max-size', '--min-size', '--compare-dest', '--copy-dest', '--link-dest', '--compress-level', '--compress-choice', '--log-file-format', '--outbuf', '--info', '--debug', '--checksum-choice', '--iconv', '--protocol', '--stop-after', '--stop-at', '--write-batch', '--read-batch', '--modify-window', '-@', '--block-size', '-B']) {
  test(`rsync value consumes preview-shaped operand: ${option}`, () => {
    expectRule(`rsync --delete ${option} -n src/ dst/`, 'sync.delete');
    noMandatory(`rsync --delete ${option} temp --dry-run src/ dst/`);
    noMandatory(`rsync --delete ${option}=-n --dry-run src/ dst/`);
  });
}
for (const command of ['rsync --delete --future-option -n src/ dst/', 'rsync --delete --dry-run --future-option src/ dst/', 'rsync --delete -Qn src/ dst/', 'rsync --delete -- --dry-run src/ dst/']) {
  test(`unproven rsync preview: ${command}`, () => expectRule(command, 'sync.delete'));
}
for (const command of [
  "psql -c 'WITH x AS (SELECT 1) DELETE FROM users'",
  "psql -c 'WITH x AS (SELECT 1 WHERE true) DELETE FROM users'",
  "psql -c 'WITH x(a) AS MATERIALIZED (SELECT 1), y AS (SELECT 2) DELETE FROM users'",
  "psql -c 'WITH x AS (DELETE FROM users RETURNING id) SELECT * FROM x'",
  "psql -c 'WITH x AS (WITH y AS (SELECT 1) DELETE FROM users RETURNING id) SELECT * FROM x'",
  'mongosh --eval "db.users.deleteMany({})"', 'mongo --eval "db.users.remove({})"',
  'mongo --eval "db.users.remove({}, false)"',
]) test(`bulk database CTE/Mongo: ${command}`, () => expectRule(command, 'database.bulk-delete'));
for (const command of [
  `psql -c "WITH x AS (SELECT 'DELETE FROM users') SELECT * FROM x"`,
  `psql -c "WITH x AS (SELECT 1) DELETE FROM users WHERE id=1"`,
  `psql -c "SELECT 'WITH x AS (SELECT 1) DELETE FROM users'"`,
  `mongosh --eval 'print("db.users.deleteMany({})")'`,
]) test(`SQL/Mongo literal or filtered neighbor: ${command}`, () => noMandatory(command));
for (const command of [
  `psql -c 'DO $$ BEGIN EXECUTE query; END $$'`,
  `psql -c 'WITH unsupported syntax'`,
  `mongosh --eval 'runCleanup()'`,
  `mongo --eval 'db.users.remove({}, true)'`,
]) test(`complex database body review, not bulk assertion: ${command}`, () => {
  expectRule(command, 'database.code');
  assert.equal(findings(command).some(f => f.ruleId === 'database.bulk-delete'), false);
});
for (const command of ['wipefs --no-act --all /dev/sdb', 'wipefs -na /dev/sdb', 'wipefs --all -n /dev/sdb', 'wipefs --help /dev/sdb', 'wipefs --all --help /dev/sdb', 'wipefs /dev/sdb']) {
  test(`wipefs documented inspection: ${command}`, () => noMandatory(command));
}
for (const command of ['wipefs --all --dry-run /dev/sdb', 'wipefs --all -- --no-act /dev/sdb', 'mkfs.ext4 --no-act /dev/sdb', 'mdadm --zero-superblock --dry-run /dev/sdb']) {
  test(`fake disk preview is not inspection: ${command}`, () => expectRule(command, 'disk.destroy', 'hard-block'));
}
test('wipefs preview-shaped value operands are not flags', () => {
  expectRule('wipefs --all --offset -n /dev/sdb', 'disk.destroy', 'hard-block');
  expectRule('wipefs --all --output --no-act /dev/sdb', 'disk.destroy', 'hard-block');
  noMandatory('wipefs --all --lock --no-act /dev/sdb');
});
test('interpreter data is not fabricated shell execution in projection', () => {
  for (const command of [
    `node -e "console.log('mkfs.ext4 /dev/sda')"`,
    `node -e "require('child_process').execSync('mkfs.ext4 /dev/sda')"`,
  ]) {
    expectRule(command, 'shell.interpreter');
    assert.equal(/mkfs|\/dev\/sda/.test(executableCommandText(command)), false);
  }
  expectRule(`node -e "console.log('$(git stash clear)')"`, 'git.stash-destruction');
  expectRule(`bash -c 'mkfs.ext4 /dev/sda'`, 'disk.destroy', 'hard-block');
});
test('hostile repeated expansions and deterministic size/token bounds', t => {
  for (const n of [8000, 16000, 32000]) {
    const command = 'echo ' + '${'.repeat(n);
    const start = performance.now();
    expectRule(command, 'shell.incomplete');
    assert.equal(executableCommandText(command), 'echo');
    const elapsed = performance.now() - start;
    t.diagnostic(`${n} expansions, evaluate + projection: ${elapsed.toFixed(2)} ms`);
    // Generous smoke budget, not a tight timing gate. Structural bounds below
    // are deterministic; measured sub-200ms evidence is reported separately.
    assert.ok(elapsed < 2000, `unbounded repeated expansion scan: ${elapsed} ms`);
  }
  for (const command of [
    'echo ' + 'a'.repeat(128 * 1024) + '; mkfs.ext4 /dev/sda',
    'echo ' + 'é'.repeat(70 * 1024) + '; mkfs.ext4 /dev/sda',
    'true; '.repeat(5000) + 'mkfs.ext4 /dev/sda',
  ]) {
    expectRule(command, 'shell.incomplete');
    assert.equal(findings(command).some(f => f.enforcement === 'hard-block'), false);
    assert.equal(executableCommandText(command), '');
  }
});

test('falsification: new semantic fixtures reject focused regressions', async () => {
  const source = await readFile(new URL('../extensions/command-safety.ts', import.meta.url), 'utf8');
  const cases = [
    ['omit force config', 'g.configs.some(c => {', '[].some(c => {',
      module => expectRule('git -c remote.origin.push=+HEAD:main push origin', 'git.force-push-config', 'hard-block', module.evaluateLocalCommand)],
    ['omit switch discard', 'sub.value === "switch" && has(o, "-f", "--force", "--discard-changes")', 'false',
      module => expectRule('git switch -f feature', 'git.working-tree-discard', 'human-required', module.evaluateLocalCommand)],
    ['lose CTE executable DML', 'sqlBodies(s).bodies.some', '[s].some',
      module => expectRule(`psql -c 'WITH x AS (SELECT 1) DELETE FROM users'`, 'database.bulk-delete', 'human-required', module.evaluateLocalCommand)],
    ['ignore rsync unknown preview', '(o.unknown || !has(o, "-n", "--dry-run"))', '(!has(o, "-n", "--dry-run"))',
      module => expectRule('rsync --delete --future-option -n src dst', 'sync.delete', 'human-required', module.evaluateLocalCommand)],
    ['lose wipefs no-act', '!has(o, "-n", "--no-act", "-h", "--help", "-V", "--version")', 'true',
      module => assert.deepEqual(module.evaluateLocalCommand('wipefs --all --no-act /dev/sdb', cwd), [])],
    ['globalize named lease', '|| blanketLease ||', '|| blanketLease || leases.length > 0 ||',
      module => assert.deepEqual(module.evaluateLocalCommand('git push --force-with-lease=refs/heads/feature origin HEAD:main', cwd), [])],
    ['project unsupported interpreter body', 'projection.push(cmd); // Interpreter operands are not shell source.', 'projection.push(words.map(w => w.value).join(" "));',
      module => assert.equal(/mkfs/.test(module.executableCommandText(`node -e "console.log('mkfs.ext4 /dev/sda')"`)), false)],
  ];
  for (const [label, from, to, verify] of cases) {
    assert.ok(source.includes(from), `mutation anchor: ${label}`);
    const mutated = stripTypeScriptTypes(source.replace(from, to));
    const module = await import(`data:text/javascript;base64,${Buffer.from(mutated).toString('base64')}#${encodeURIComponent(label)}`);
    assert.throws(() => verify(module), { code: 'ERR_ASSERTION' }, label);
  }
});

// Red-capability, not just a green snapshot: load targeted broken copies IN MEMORY.
// Assert the SAME semantic expectation fails for the named omission, not import/syntax.
// No source file is changed; dangerous fixtures are still only evaluator input strings.
test('falsification: fixtures reject targeted rule omissions', async () => {
  const source = await readFile(new URL('../extensions/command-safety.ts', import.meta.url), 'utf8');
  const mutations = [
    ['omit Git rules', '      gitFindings(g.args, add);', '      /* mutation: omit Git rules */', 'git stash clear', 'git.stash-destruction', 'human-required'],
    ['ignore plus refspec', 'r.value.startsWith("+")', 'false', 'git push origin +HEAD:main', 'git.force-push-protected', 'hard-block'],
    ['ignore rsync deletion', 'k.startsWith("--delete")', 'false', 'rsync --delete src dst', 'sync.delete', 'human-required'],
    ['ignore SQL comments', 'match => /^(?:--|\\/\\*)/.test(match) ? " " : " __literal__ "', '() => " __literal__ "', 'psql -c "/* cleanup */ DROP TABLE users"', 'database.bulk-delete', 'human-required'],
    ['lose repeated SQL options', 'for (const body of codes)', 'for (const body of codes.slice(-1))', 'psql -c "DROP TABLE users" -c "SELECT 1"', 'database.bulk-delete', 'human-required'],
  ];
  for (const [label, from, to, command, ruleId, enforcement] of mutations) {
    assert.ok(source.includes(from), `mutation anchor: ${label}`);
    const mutated = stripTypeScriptTypes(source.replace(from, to));
    const module = await import(`data:text/javascript;base64,${Buffer.from(mutated).toString('base64')}#${encodeURIComponent(label)}`);
    assert.throws(() => expectRule(command, ruleId, enforcement, module.evaluateLocalCommand), { code: 'ERR_ASSERTION' }, label);
  }
});

test('a literal tautology is not a row filter for bulk DELETE', () => {
  // SQL DELETE selects every matching row; TRUE and identical integer equality
  // match every row. This is not a general SQL predicate solver.
  for (const query of ['DELETE FROM users WHERE TRUE', 'DELETE FROM users WHERE 1=1', 'DELETE FROM users WHERE ((TRUE)) RETURNING id']) {
    expectRule(`psql -c '${query}'`, 'database.bulk-delete');
  }
  for (const query of ['DELETE FROM users WHERE FALSE', 'DELETE FROM users WHERE 1=2', 'DELETE FROM users WHERE TRUE AND id=1']) {
    noMandatory(`psql -c '${query}'`);
  }
});

test('trap executable hooks require review, unlike querying existing traps', () => {
  expectRule(`trap 'cleanup' EXIT`, 'shell.incomplete');
  expectRule(`trap 'rm -rf ./cache' EXIT`, 'shell.incomplete');
  noMandatory('trap -p');
  noMandatory('trap -l');
});

test('project-relative cleanup under home needs a human, not a fabricated root block', () => {
  for (const root of ['/Users/nils/project', '/home/nils/project']) {
    for (const command of ['rm -rf build', 'rm -rf .', 'cd src && rm -rf generated']) {
      const result = evaluateLocalCommand(command, root);
      assert.ok(result.some(f => f.enforcement === 'human-required'), command);
      assert.equal(result.some(f => f.enforcement === 'hard-block'), false, `${root}: ${command}`);
    }
  }
  for (const root of ['/', '/Users/nils', '/home/nils', '/etc']) {
    assert.ok(evaluateLocalCommand('rm -rf .', root).some(f => f.enforcement === 'hard-block'), root);
  }
});
