package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testing.EnforcementFixtures;
import io.github.hectorvent.floci.testing.IamEnforcementProfile;
import io.github.hectorvent.floci.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static io.github.hectorvent.floci.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * REST requests whose route no rule mapped to an IAM action were let through under enforcement
 * unchecked. These routes are mapped now, and a caller needs the action AWS checks for them.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class IamRestRouteEnforcementIntegrationTest {

    private static final String ADMIN = "test";
    private static final String ACCOUNT = "000000000000";

    @TestHTTPResource("/")
    static URI baseUri;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    /** Each user's access key ID, by user name. */
    private final Map<String, String> keys = new HashMap<>();

    @Test
    void apiGatewayManagementRoutesBeyondRestApisAreCheckedByMethod() {
        String user = user("route-apigateway");
        String plan = "{\"name\":\"route-plan-" + suffix() + "\"}";

        policy(user, allow("apigateway:GET", "*"));
        refused(as(user, "apigateway").body(plan).post("/usageplans").then(), "apigateway:POST");
        as(user, "apigateway").get("/usageplans").then().statusCode(200);

        policy(user, allow("apigateway:POST", "*"));
        String id = as(user, "apigateway").body(plan).post("/usageplans").then().statusCode(201).extract().path("id");
        cleanup.register(() -> given().header("Authorization", auth(ADMIN, "apigateway")).delete("/usageplans/" + id));
    }

    @Test
    void getLayerVersionByArnIsCheckedAsGetLayerVersion() {
        String user = user("route-layer");
        String arn = "arn:aws:lambda:us-east-1:" + ACCOUNT + ":layer:route-layer-" + suffix() + ":1";

        policy(user, allow("lambda:ListLayers", "*"));
        refused(as(user, "lambda").queryParam("find", "LayerVersion").queryParam("Arn", arn)
                .get("/2018-10-31/layers").then(), "lambda:GetLayerVersion");
        policy(user, allow("lambda:GetLayerVersion", "*"));
        // Allowed, the request reaches Lambda, which has no such layer.
        as(user, "lambda").queryParam("find", "LayerVersion").queryParam("Arn", arn)
                .get("/2018-10-31/layers").then().statusCode(404);
    }

    @Test
    void aScheduleRequestSignedForAnotherServiceIsStillCheckedAsScheduler() {
        // Checked by the route it reached, not by the credential scope it was signed with: an S3
        // grant does not let the request through as an S3 request.
        String user = user("route-scheduler-scope");
        policy(user, allow("s3:*", "*"));
        refused(as(user, "s3").get("/schedules/route-schedule-" + suffix()).then(), "scheduler:GetSchedule");
    }

    @Test
    void schedulerTaggingIsCheckedOnTheBareTagsRouteToo() {
        // The shared tagging routes also take the ARN in the body of POST /tags.
        String user = user("route-scheduler-tags");
        String group = scheduleGroup("route-group-" + suffix());

        policy(user, allow("scheduler:ListTagsForResource", "*"));
        refused(as(user, "scheduler").body(tagBody(group)).post("/tags").then(), "scheduler:TagResource");
        policy(user, allow("scheduler:TagResource", group));
        // Allowed on that group, the request reaches Scheduler, which has no such group.
        as(user, "scheduler").body(tagBody(group)).post("/tags").then().statusCode(not(403));
    }

    @Test
    void postTagsIsCheckedAgainstTheArnItsBodyNames() {
        // POST /tags tags the ARN its body names: one named in the query does not move the check.
        String user = user("route-tags-body");
        String allowed = scheduleGroup("route-allowed-" + suffix());
        String other = scheduleGroup("route-other-" + suffix());

        policy(user, allow("scheduler:TagResource", allowed));
        refused(as(user, "scheduler").queryParam("resourceArn", allowed).body(tagBody(other)).post("/tags").then(),
                "scheduler:TagResource");
    }

    @Test
    void sharedTaggingIsCheckedAsTheServiceItsArnNames() {
        // The shared tagging routes hand the request to the service its ARN names, whatever scope it is
        // signed with: a Pipes grant does not let the caller tag a schedule group, and a scope with no
        // tagging rule does not let the request through unchecked.
        String user = user("route-tags-scope");
        String group = scheduleGroup("route-group-" + suffix());
        String cluster = "arn:aws:eks:us-east-1:" + ACCOUNT + ":cluster/route-cluster-" + suffix();

        // Nor is an ARN of a service with no tagging rule checked as the signing scope's action.
        as(user, "pipes").body(tagBody(cluster)).post("/tags").then().body(not(containsString("pipes:TagResource")));
        policy(user, allow("pipes:TagResource", "*"));
        refused(as(user, "pipes").body(tagBody(group)).post("/tags").then(), "scheduler:TagResource");
        refused(as(user, "sqs").body(tagBody(group)).post("/tags").then(), "scheduler:TagResource");
    }

    private static String scheduleGroup(String name) {
        return "arn:aws:scheduler:us-east-1:" + ACCOUNT + ":schedule-group/" + name;
    }

    private static String tagBody(String arn) {
        return "{\"resourceArn\":\"" + arn + "\",\"tags\":[{\"key\":\"team\",\"value\":\"a\"}]}";
    }

    private static void refused(ValidatableResponse response, String action) {
        response.statusCode(403).body(containsString(action)).body(not(containsString("iam:PassRole")));
    }

    private static String allow(String action, String resource) {
        return "{\"Effect\":\"Allow\",\"Action\":\"" + action + "\",\"Resource\":\"" + resource + "\"}";
    }

    private void policy(String user, String statements) {
        EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth(ADMIN, "iam"), user, "p",
                "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
    }

    /** Creates a user, removed afterwards, and returns its access key ID under the user's name. */
    private String user(String name) {
        String userName = name + "-" + suffix();
        String accessKeyId = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ADMIN, "iam"), userName)
                .accessKeyId();
        keys.put(userName, accessKeyId);
        return userName;
    }

    private RequestSpecification as(String user, String service) {
        return given().header("Authorization", auth(keys.get(user), service)).contentType("application/json");
    }

    private static String suffix() {
        return Long.toString(System.nanoTime(), 36);
    }
}
