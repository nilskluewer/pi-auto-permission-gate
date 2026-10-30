import assert from "node:assert/strict";
import test from "node:test";
import {
	DEFAULT_PRODUCTION_PATTERNS, NON_PRODUCTION_MARKERS, ALWAYS_CRITICAL_REASONS,
	environmentIdentifiers, classifyEnvironment, isAccessChange, assessCriticality,
} from "../extensions/criticality.mjs";

const cloud = "cloud or infrastructure change";
// Oracle: /tmp/pg-fatigue-contracts.md, Module A. These pairs reject policies
// that soften unknown targets, let dev override prod, or make all cloud work critical.
test("exports the agreed policy defaults", () => {
	assert.deepEqual(DEFAULT_PRODUCTION_PATTERNS, ["prod", "prd", "production"]);
	assert.ok(NON_PRODUCTION_MARKERS.includes("sandbox"));
	assert.deepEqual(ALWAYS_CRITICAL_REASONS, ["sudo", "disk shred/wipe", "partition editor"]);
});

test("extracts environment identifiers from flags, resources, contexts and workspaces", () => {
	for (const [command, expected] of [
		["gcloud run deploy api --project=Team-DEV", "team-dev"],
		["aws s3 rm s3://Team-PRD/data --profile sandbox", "team-prd"],
		["gcloud storage rm gs://Team-Prod/data", "team-prod"],
		["bq rm team-test:dataset.table", "team-test"],
		["bq rm team-prod.dataset.table", "team-prod"],
		["kubectl config use-context TEAM-STG", "team-stg"],
		["terraform workspace select TEAM-QA", "team-qa"],
		["az group delete --resource-group Team-DEV", "team-dev"],
	]) assert.ok(environmentIdentifiers(command).includes(expected), command);
});

test("classifies whole identifiers and segments with production precedence", () => {
	for (const command of ["gcloud storage rm gs://data-PROD/x", "aws s3 rm s3://team-prd/x", "kubectl delete pod x --context team.production --namespace dev"])
		assert.equal(classifyEnvironment(command), "production", command);
	for (const marker of NON_PRODUCTION_MARKERS)
		assert.equal(classifyEnvironment(`gcloud run deploy api --project team-${marker}`), "non-production", marker);
	assert.equal(classifyEnvironment("gcloud run deploy api --project team-blue"), "unknown");
	assert.equal(classifyEnvironment("gcloud run deploy api"), "unknown");
	assert.equal(classifyEnvironment("gcloud run deploy api --project product"), "unknown");
	assert.equal(classifyEnvironment("gcloud run deploy api --project team-live7", ["live?"]), "production");
	assert.equal(classifyEnvironment("gcloud run deploy api --project account-release-eu", ["account-*-eu"]), "production");
	assert.equal(classifyEnvironment("gcloud run deploy api --project dev --label=prod"), "non-production");
});

test("IAM and credential minting stay access changes on dev", () => {
	for (const command of [
		"gcloud projects set-iam-policy dev policy.json",
		"gcloud projects add-iam-policy-binding dev --member=user:a",
		"gcloud projects remove-iam-policy-binding dev --member=user:a",
		"gcloud iam service-accounts create bot --project dev",
		"gcloud iam service-accounts keys create key.json --iam-account bot --project dev",
		"gcloud iam roles update role --project dev",
		"gcloud auth print-access-token --project dev",
		"gcloud run deploy app --project dev --impersonate-service-account=bot",
		"aws iam create-role --role-name dev", "aws iam attach-role-policy --role-name dev",
		"az role assignment create --resource-group dev", "az role assignment delete --resource-group dev",
		"az --subscription dev role assignment create", "/usr/bin/aws iam delete-role --role-name dev",
		"gcloud iam --project dev service-accounts create bot",
		"kubectl create clusterrolebinding dev", "kubectl apply rolebinding dev",
	]) {
		assert.equal(isAccessChange(command), true, command);
		assert.equal(assessCriticality(command, [cloud]).critical, true, command);
	}
	for (const command of ["gcloud run deploy app --project dev", "aws iam list-roles", "aws iam get-role --role-name dev", "aws iam --profile dev list-roles", "az role assignment list", "kubectl get rolebinding dev"])
		assert.equal(isAccessChange(command), false, command);
});

test("criticality partitions reasons and only cloud reasons set an environment", () => {
	assert.deepEqual(assessCriticality("gcloud storage rm gs://team-dev/x", [cloud, "interpreter or script execution"]), {
		critical: false, criticalReasons: [], grantableReasons: [cloud, "interpreter or script execution"], environment: "non-production", accessChange: false,
	});
	for (const target of ["team-prod", "team-blue"])
		assert.equal(assessCriticality(`gcloud storage rm gs://${target}/x`, [cloud]).critical, true);
	const result = assessCriticality("sudo cat x", ["sudo", "sensitive path"]);
	assert.deepEqual(result.criticalReasons, ["sudo"]);
	assert.deepEqual(result.grantableReasons, ["sensitive path"]);
	assert.equal(result.environment, undefined);
	assert.equal(assessCriticality("gcloud projects describe team-prod", ["sensitive path"]).critical, false);
	assert.equal(assessCriticality("gcloud run deploy api --project team-live", [cloud], { productionPatterns: ["*live"] }).environment, "production");
	for (const reason of ALWAYS_CRITICAL_REASONS)
		assert.equal(assessCriticality("anything --project dev", [reason]).critical, true);
});
