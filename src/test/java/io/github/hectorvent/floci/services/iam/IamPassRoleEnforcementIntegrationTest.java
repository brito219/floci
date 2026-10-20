package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import io.github.hectorvent.floci.testing.EnforcementFixtures;
import io.github.hectorvent.floci.testing.IamEnforcementProfile;
import io.github.hectorvent.floci.testing.PartitionCleanup;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.zip.GZIPOutputStream;

import static io.github.hectorvent.floci.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A request that passes a role to a service also needs {@code iam:PassRole} on that role, with
 * {@code iam:PassedToService} naming the service, as the IAM user guide requires: "To pass a role
 * (and its permissions) to an AWS service, a user must have permissions to pass the role to the
 * service." Without it a user allowed only to create functions, launch instances or run tasks could
 * hand them any role in the account and act with its permissions.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class IamPassRoleEnforcementIntegrationTest {

    private static final String ADMIN = "test";
    private static final String ACCOUNT = "000000000000";
    private static final String IMAGE = "ami-0abcdef1234567890";
    private static final String ECS_TASKS = "ecs-tasks.amazonaws.com";
    private static final String ECS = "ecs.amazonaws.com";
    private static final String QUEUE_ARN = "arn:aws:sqs:us-east-1:" + ACCOUNT + ":passrole-queue";
    private static final String SCHEDULER = "scheduler.amazonaws.com";
    private static final String PIPES = "pipes.amazonaws.com";
    private static final ObjectMapper CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    @TestHTTPResource("/")
    static URI baseUri;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void creatingAFunctionNeedsPassRoleOnItsExecutionRoleForLambda() {
        String role = role("fn-exec");
        User user = user("passrole-create-fn");
        String name = "passrole-fn-" + suffix();
        String body = """
                {"FunctionName":"%s","Runtime":"nodejs20.x","Handler":"index.handler","Role":"%s"}"""
                .formatted(name, role);

        user.policy(allow("lambda:CreateFunction", "*"));
        denied(user.lambda().body(body).post("/2015-03-31/functions").then());

        // The permission names the service the role is passed to: one for EC2 does not cover Lambda.
        user.policy(allow("lambda:CreateFunction", "*") + "," + passRole(role, "ec2.amazonaws.com"));
        denied(user.lambda().body(body).post("/2015-03-31/functions").then());

        user.policy(allow("lambda:CreateFunction", "*") + "," + passRole(role, "lambda.amazonaws.com"));
        user.lambda().body(body).post("/2015-03-31/functions").then().statusCode(201);
        cleanup.register(() -> admin("lambda").contentType("application/json")
                .delete("/2015-03-31/functions/{name}", name));
    }

    @Test
    void updatingAFunctionNeedsPassRoleOnlyWhenItSetsTheRole() {
        String first = role("fn-first");
        String second = role("fn-second");
        String name = "passrole-update-" + suffix();
        admin("lambda").contentType("application/json")
                .body("""
                        {"FunctionName":"%s","Runtime":"nodejs20.x","Handler":"index.handler","Role":"%s"}"""
                        .formatted(name, first))
                .post("/2015-03-31/functions").then().statusCode(201);
        cleanup.register(() -> admin("lambda").contentType("application/json")
                .delete("/2015-03-31/functions/{name}", name));
        User user = user("passrole-update-fn");
        String configuration = "/2015-03-31/functions/" + name + "/configuration";

        user.policy(allow("lambda:UpdateFunctionConfiguration", "*"));
        user.lambda().body("{\"Timeout\":10}").put(configuration).then().statusCode(200);
        denied(user.lambda().body("{\"Role\":\"" + second + "\"}").put(configuration).then());

        user.policy(allow("lambda:UpdateFunctionConfiguration", "*") + ","
                + passRole(second, "lambda.amazonaws.com"));
        user.lambda().body("{\"Role\":\"" + second + "\"}").put(configuration).then().statusCode(200);
    }

    @Test
    void aWebFunctionNeedsPassRoleOnItsExecutionRole() {
        String role = role("web-exec");
        User user = user("passrole-web-fn");
        String name = "passrole-web-" + suffix();
        String function = """
                {"functionName":"%s","revisionConfig":{"serviceConfig":{"executionRoleArn":"%s"}}}"""
                .formatted(name, role);
        String revision = "{\"serviceConfig\":{\"executionRoleArn\":\"" + role + "\"}}";

        user.policy(allow("lambda:CreateWebFunction", "*") + "," + allow("lambda:CreateWebFunctionRevision", "*"));
        denied(user.lambda().body(function).put("/2025-03-07/web-functions").then());
        denied(user.lambda().body(revision).post("/2025-03-07/web-functions/" + name + "/revisions").then());

        // With the permission the request reaches Lambda, which answers it on its own terms.
        user.policy(allow("lambda:CreateWebFunction", "*") + "," + allow("lambda:CreateWebFunctionRevision", "*")
                + "," + passRole(role, "lambda.amazonaws.com"));
        user.lambda().body(function).put("/2025-03-07/web-functions").then().statusCode(not(403));
        user.lambda().body(revision).post("/2025-03-07/web-functions/" + name + "/revisions").then()
                .statusCode(not(403));
        cleanup.register(() -> admin("lambda").delete("/2025-03-07/web-functions/{name}", name));
    }

    @Test
    void anInstanceProfileNeedsPassRoleOnItsRoleWhenAnInstanceIsLaunchedOrAssociated() {
        String role = role("ec2-instance");
        String roleName = role.substring(role.lastIndexOf('/') + 1);
        String profile = instanceProfile(roleName);
        String profileArn = "arn:aws:iam::" + ACCOUNT + ":instance-profile/" + profile;
        User user = user("passrole-ec2");

        user.policy(allow("ec2:RunInstances", "*") + "," + allow("ec2:AssociateIamInstanceProfile", "*"));
        denied(user.ec2("RunInstances").formParam("ImageId", IMAGE).formParam("InstanceType", "t3.micro")
                .formParam("MinCount", "1").formParam("MaxCount", "1")
                .formParam("IamInstanceProfile.Name", profile).post("/").then());
        String instanceId = user.ec2("RunInstances").formParam("ImageId", IMAGE).formParam("InstanceType", "t3.micro")
                .formParam("MinCount", "1").formParam("MaxCount", "1").post("/").then().statusCode(200)
                .extract().xmlPath().getString("RunInstancesResponse.instancesSet.item.instanceId");
        terminateLater(instanceId);
        denied(user.ec2("AssociateIamInstanceProfile").formParam("InstanceId", instanceId)
                .formParam("IamInstanceProfile.Arn", profileArn).post("/").then());
        // A profile that does not exist passes no role; EC2 refuses it as it would without enforcement.
        user.ec2("RunInstances").formParam("ImageId", IMAGE).formParam("InstanceType", "t3.micro")
                .formParam("MinCount", "1").formParam("MaxCount", "1")
                .formParam("IamInstanceProfile.Name", "no-such-profile").post("/").then().statusCode(400)
                .body(containsString("InvalidParameterValue"));

        user.policy(allow("ec2:RunInstances", "*") + "," + allow("ec2:AssociateIamInstanceProfile", "*") + ","
                + passRole(role, "ec2.amazonaws.com"));
        terminateLater(user.ec2("RunInstances").formParam("ImageId", IMAGE).formParam("InstanceType", "t3.micro")
                .formParam("MinCount", "1").formParam("MaxCount", "1")
                .formParam("IamInstanceProfile.Name", profile).post("/").then().statusCode(200)
                .extract().xmlPath().getString("RunInstancesResponse.instancesSet.item.instanceId"));
        String associationId = user.ec2("AssociateIamInstanceProfile").formParam("InstanceId", instanceId)
                .formParam("IamInstanceProfile.Arn", profileArn).post("/").then().statusCode(200)
                .extract().xmlPath().getString(
                        "AssociateIamInstanceProfileResponse.iamInstanceProfileAssociation.associationId");

        // Replacing the association passes the new profile's role.
        String other = role("ec2-replacement");
        String otherProfile = instanceProfile(other.substring(other.lastIndexOf('/') + 1));
        user.policy(allow("ec2:ReplaceIamInstanceProfileAssociation", "*") + "," + passRole(role, "ec2.amazonaws.com"));
        denied(user.ec2("ReplaceIamInstanceProfileAssociation").formParam("AssociationId", associationId)
                .formParam("IamInstanceProfile.Name", otherProfile).post("/").then());
        user.policy(allow("ec2:ReplaceIamInstanceProfileAssociation", "*") + "," + passRole(other, "ec2.amazonaws.com"));
        user.ec2("ReplaceIamInstanceProfileAssociation").formParam("AssociationId", associationId)
                .formParam("IamInstanceProfile.Name", otherProfile).post("/").then().statusCode(200);
    }

    @Test
    void aSpotInstanceRequestNeedsPassRoleOnItsInstanceProfilesRole() {
        String role = role("ec2-spot");
        String profile = instanceProfile(role.substring(role.lastIndexOf('/') + 1));
        String profileArn = "arn:aws:iam::" + ACCOUNT + ":instance-profile/" + profile;
        User user = user("passrole-spot");

        user.policy(allow("ec2:RequestSpotInstances", "*"));
        denied(spotRequest(user, "Arn", profileArn).then());
        denied(spotRequest(user, "Name", profile).then());

        user.policy(allow("ec2:RequestSpotInstances", "*") + "," + passRole(role, "ec2.amazonaws.com"));
        assertEquals(profileArn, spotProfileArn(user, "Arn", profileArn));
        // A profile named rather than given by ARN is the same profile, and the instance gets it.
        assertEquals(profileArn, spotProfileArn(user, "Name", profile));
    }

    @Test
    void aLaunchTemplateWithAnInstanceProfileNeedsPassRoleOnItsRole() {
        String role = role("ec2-template");
        String profile = instanceProfile(role.substring(role.lastIndexOf('/') + 1));
        User user = user("passrole-template");
        String name = "passrole-template-" + suffix();

        user.policy(allow("ec2:CreateLaunchTemplate", "*"));
        denied(user.ec2("CreateLaunchTemplate").formParam("LaunchTemplateName", name)
                .formParam("LaunchTemplateData.ImageId", IMAGE)
                .formParam("LaunchTemplateData.IamInstanceProfile.Name", profile).post("/").then());

        user.policy(allow("ec2:CreateLaunchTemplate", "*") + "," + passRole(role, "ec2.amazonaws.com"));
        user.ec2("CreateLaunchTemplate").formParam("LaunchTemplateName", name)
                .formParam("LaunchTemplateData.ImageId", IMAGE)
                .formParam("LaunchTemplateData.IamInstanceProfile.Name", profile).post("/").then().statusCode(200);
        cleanup.register(() -> admin("ec2").formParam("Action", "DeleteLaunchTemplate")
                .formParam("LaunchTemplateName", name).post("/"));

        // A new version of the template passes its profile's role too.
        user.policy(allow("ec2:CreateLaunchTemplateVersion", "*"));
        denied(user.ec2("CreateLaunchTemplateVersion").formParam("LaunchTemplateName", name)
                .formParam("LaunchTemplateData.ImageId", IMAGE)
                .formParam("LaunchTemplateData.IamInstanceProfile.Name", profile).post("/").then());
        user.policy(allow("ec2:CreateLaunchTemplateVersion", "*") + "," + passRole(role, "ec2.amazonaws.com"));
        user.ec2("CreateLaunchTemplateVersion").formParam("LaunchTemplateName", name)
                .formParam("LaunchTemplateData.ImageId", IMAGE)
                .formParam("LaunchTemplateData.IamInstanceProfile.Name", profile).post("/").then().statusCode(200);
    }

    @Test
    void aFlowLogNeedsPassRoleOnItsDeliveryRoleForFlowLogs() {
        String role = role("flow-logs");
        String vpcId = admin("ec2").formParam("Action", "DescribeVpcs").post("/").then().statusCode(200)
                .extract().xmlPath().getString("DescribeVpcsResponse.vpcSet.item[0].vpcId");
        User user = user("passrole-flow-logs");

        user.policy(allow("ec2:CreateFlowLogs", "*"));
        denied(flowLog(user, vpcId, role).then());

        user.policy(allow("ec2:CreateFlowLogs", "*") + "," + passRole(role, "vpc-flow-logs.amazonaws.com"));
        String flowLogId = flowLog(user, vpcId, role).then().statusCode(200)
                .extract().xmlPath().getString("CreateFlowLogsResponse.flowLogIdSet.item");
        cleanup.register(() -> admin("ec2").formParam("Action", "DeleteFlowLogs")
                .formParam("FlowLogId.1", flowLogId).post("/"));
    }

    @Test
    void aTaskDefinitionNeedsPassRoleOnItsTaskAndExecutionRolesForEcsTasks() {
        String taskRole = role("ecs-task");
        String executionRole = role("ecs-execution");
        User user = user("passrole-ecs-register");
        String family = "passrole-family-" + suffix();
        String body = taskDefinition(family, taskRole, executionRole);

        user.policy(allow("ecs:RegisterTaskDefinition", "*") + "," + passRole(taskRole, ECS_TASKS));
        deniedJson(user.ecs("RegisterTaskDefinition").body(body).post("/").then());

        // Task roles go to ecs-tasks.amazonaws.com: a grant for ecs.amazonaws.com does not cover them.
        user.policy(allow("ecs:RegisterTaskDefinition", "*") + "," + passRole(taskRole, ECS_TASKS) + ","
                + passRole(executionRole, ECS));
        deniedJson(user.ecs("RegisterTaskDefinition").body(body).post("/").then());

        user.policy(allow("ecs:RegisterTaskDefinition", "*") + "," + passRole(taskRole, ECS_TASKS) + ","
                + passRole(executionRole, ECS_TASKS));
        user.ecs("RegisterTaskDefinition").body(body).post("/").then().statusCode(200);
        deregisterLater(family + ":1");

        // A task role given by its name is the role of that name in the caller's account.
        String named = taskDefinition(family, roleName(taskRole), null);
        user.policy(allow("ecs:RegisterTaskDefinition", "*"));
        deniedJson(user.ecs("RegisterTaskDefinition").body(named).post("/").then());
        user.policy(allow("ecs:RegisterTaskDefinition", "*") + "," + passRole(taskRole, ECS_TASKS));
        user.ecs("RegisterTaskDefinition").body(named).post("/").then().statusCode(200);
        deregisterLater(family + ":2");
    }

    @Test
    void runningATaskNeedsPassRoleOnItsTaskDefinitionsRolesAndOnAnyOverride() {
        String taskRole = role("ecs-run");
        String override = role("ecs-override");
        String family = registerTaskDefinition(taskRole);
        String cluster = cluster();
        User user = user("passrole-ecs-run");

        // The caller names no role: the one it passes is the task definition's.
        user.policy(allow("ecs:RunTask", "*"));
        deniedJson(user.ecs("RunTask").body(runTask(cluster, family, null)).post("/").then());

        user.policy(allow("ecs:RunTask", "*") + "," + passRole(taskRole, ECS_TASKS));
        stopLater(cluster, user.ecs("RunTask").body(runTask(cluster, family, null)).post("/").then()
                .statusCode(200).extract().path("tasks[0].taskArn"));

        // An override is passed as well.
        deniedJson(user.ecs("RunTask").body(runTask(cluster, family, override)).post("/").then());
        user.policy(allow("ecs:RunTask", "*") + "," + passRole(taskRole, ECS_TASKS) + ","
                + passRole(override, ECS_TASKS));
        stopLater(cluster, user.ecs("RunTask").body(runTask(cluster, family, override)).post("/").then()
                .statusCode(200).extract().path("tasks[0].taskArn"));
    }

    @Test
    void aServiceNeedsPassRoleOnItsTaskDefinitionsRolesAndOnItsInfrastructureRoles() {
        String taskRole = role("ecs-service");
        String nextRole = role("ecs-service-next");
        String infrastructure = role("ecs-infrastructure");
        String family = registerTaskDefinition(taskRole);
        String next = registerTaskDefinition(nextRole);
        String cluster = cluster();
        String name = "passrole-svc-" + suffix();
        User user = user("passrole-ecs-service");

        user.policy(allow("ecs:CreateService", "*"));
        deniedJson(user.ecs("CreateService").body(service(cluster, name, family)).post("/").then());
        user.policy(allow("ecs:CreateService", "*") + "," + passRole(taskRole, ECS_TASKS));
        user.ecs("CreateService").body(service(cluster, name, family)).post("/").then().statusCode(200);
        cleanup.register(() -> admin("ecs").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.DeleteService")
                .body("{\"cluster\":\"" + cluster + "\",\"service\":\"" + name + "\",\"force\":true}").post("/"));

        // Moving the service to another task definition passes that definition's roles.
        String update = "{\"cluster\":\"" + cluster + "\",\"service\":\"" + name + "\",\"taskDefinition\":\""
                + next + "\"}";
        user.policy(allow("ecs:UpdateService", "*") + "," + passRole(taskRole, ECS_TASKS));
        deniedJson(user.ecs("UpdateService").body(update).post("/").then());
        user.policy(allow("ecs:UpdateService", "*") + "," + passRole(nextRole, ECS_TASKS));
        user.ecs("UpdateService").body(update).post("/").then().statusCode(200);

        // An infrastructure role, here an EBS volume's, is passed to ECS itself.
        String volumes = "{\"cluster\":\"" + cluster + "\",\"service\":\"" + name + "\",\"volumeConfigurations\":"
                + "[{\"name\":\"data\",\"managedEBSVolume\":{\"roleArn\":\"" + infrastructure + "\"}}]}";
        user.policy(allow("ecs:UpdateService", "*") + "," + passRole(infrastructure, ECS_TASKS));
        deniedJson(user.ecs("UpdateService").body(volumes).post("/").then());
        user.policy(allow("ecs:UpdateService", "*") + "," + passRole(infrastructure, ECS));
        // ECS answers the volume on its own terms; a JSON-protocol denial would be a 400 naming the action.
        user.ecs("UpdateService").body(volumes).post("/").then().body(not(containsString("iam:PassRole")));
    }

    @Test
    void aStateMachineNeedsPassRoleOnItsRoleForStepFunctions() throws IOException {
        String role = role("states");
        String other = role("states-other");
        User user = user("passrole-states");
        String body = """
                {"name":"passrole-sm-%s","roleArn":"%s",
                 "definition":"{\\"StartAt\\":\\"Done\\",\\"States\\":{\\"Done\\":{\\"Type\\":\\"Pass\\",\\"End\\":true}}}"}"""
                .formatted(suffix(), role);

        user.policy(allow("states:CreateStateMachine", "*"));
        deniedJson(user.states("CreateStateMachine").body(body).post("/").then());
        // A Smithy RPC v2 CBOR call names the role in the same member.
        byte[] cbor = CBOR_MAPPER.writeValueAsBytes(new ObjectMapper().readTree(body));
        assertPassRoleDenied(user.cbor("states").body(cbor)
                .post("/service/AWSStepFunctions/operation/CreateStateMachine"));
        // A gzip-encoded body, which the CBOR endpoint decompresses before it runs the request.
        assertPassRoleDenied(user.cbor("states").header("Content-Encoding", "gzip").body(gzip(cbor))
                .post("/service/AWSStepFunctions/operation/CreateStateMachine"));

        user.policy(allow("states:CreateStateMachine", "*") + "," + passRole(role, "states.amazonaws.com"));
        String arn = user.states("CreateStateMachine").body(body).post("/").then()
                .statusCode(200).extract().path("stateMachineArn");
        cleanup.register(() -> admin("states").contentType("application/x-amz-json-1.0")
                .header("X-Amz-Target", "AWSStepFunctions.DeleteStateMachine")
                .body("{\"stateMachineArn\":\"" + arn + "\"}").post("/"));

        String update = "{\"stateMachineArn\":\"" + arn + "\",\"roleArn\":\"" + other + "\"}";
        user.policy(allow("states:UpdateStateMachine", "*") + "," + passRole(role, "states.amazonaws.com"));
        deniedJson(user.states("UpdateStateMachine").body(update).post("/").then());
        user.policy(allow("states:UpdateStateMachine", "*") + "," + passRole(other, "states.amazonaws.com"));
        user.states("UpdateStateMachine").body(update).post("/").then().statusCode(200);
    }

    @Test
    void anEventBridgeRuleAndEachOfItsTargetsNeedPassRoleOnTheirRoles() {
        String role = role("events");
        String targetRole = role("events-target");
        User user = user("passrole-events");
        String rule = "passrole-rule-" + suffix();
        String putRule = "{\"Name\":\"" + rule + "\",\"ScheduleExpression\":\"rate(1 hour)\",\"RoleArn\":\""
                + role + "\"}";
        String rules = allow("events:PutRule", "*") + "," + allow("events:PutTargets", "*");

        user.policy(rules);
        deniedJson(user.json("events", "AWSEvents.PutRule").body(putRule).post("/").then());
        user.policy(rules + "," + passRole(role, "events.amazonaws.com"));
        user.json("events", "AWSEvents.PutRule").body(putRule).post("/").then().statusCode(200);
        cleanup.register(() -> admin("events").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AWSEvents.DeleteRule").body("{\"Name\":\"" + rule + "\"}").post("/"));
        cleanup.register(() -> admin("events").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AWSEvents.RemoveTargets")
                .body("{\"Rule\":\"" + rule + "\",\"Ids\":[\"1\",\"2\"]}").post("/"));

        // The second target names a role, the first does not.
        String putTargets = "{\"Rule\":\"" + rule + "\",\"Targets\":[{\"Id\":\"1\",\"Arn\":\"" + QUEUE_ARN + "\"},"
                + "{\"Id\":\"2\",\"Arn\":\"" + QUEUE_ARN + "\",\"RoleArn\":\"" + targetRole + "\"}]}";
        deniedJson(user.json("events", "AWSEvents.PutTargets").body(putTargets).post("/").then());
        user.policy(rules + "," + passRole(targetRole, "events.amazonaws.com"));
        user.json("events", "AWSEvents.PutTargets").body(putTargets).post("/").then().statusCode(200);
    }

    @Test
    void aScheduleNeedsTheSchedulerActionOnItsArnAndPassRoleOnItsTargetsRole() {
        String role = role("scheduler");
        String other = role("scheduler-other");
        User user = user("passrole-scheduler");
        String name = "passrole-schedule-" + suffix();
        String path = "/schedules/" + name;
        String arn = "arn:aws:scheduler:us-east-1:" + ACCOUNT + ":schedule/default/" + name;

        // The route is checked as scheduler:CreateSchedule, on the schedule's ARN.
        user.policy(allow("scheduler:CreateSchedule", arn + "-other") + "," + passRole(role, SCHEDULER));
        refused(user.rest("scheduler").body(schedule(role)).post(path).then(), "scheduler:CreateSchedule");
        user.policy(allow("scheduler:CreateSchedule", arn));
        denied(user.rest("scheduler").body(schedule(role)).post(path).then());
        user.policy(allow("scheduler:CreateSchedule", arn) + "," + passRole(role, SCHEDULER));
        user.rest("scheduler").body(schedule(role)).post(path).then().statusCode(200);
        cleanup.register(() -> admin("scheduler").delete(path));

        user.policy(allow("scheduler:UpdateSchedule", arn) + "," + passRole(role, SCHEDULER));
        denied(user.rest("scheduler").body(schedule(other)).put(path).then());
        user.policy(allow("scheduler:UpdateSchedule", arn) + "," + passRole(other, SCHEDULER));
        user.rest("scheduler").body(schedule(other)).put(path).then().statusCode(200);
    }

    @Test
    void aPipeNeedsThePipesActionOnItsArnAndPassRoleOnItsRole() {
        String role = role("pipes");
        String other = role("pipes-other");
        User user = user("passrole-pipes");
        String name = "passrole-pipe-" + suffix();
        String path = "/v1/pipes/" + name;
        String arn = "arn:aws:pipes:us-east-1:" + ACCOUNT + ":pipe/" + name;
        String create = "{\"Source\":\"" + QUEUE_ARN + "\",\"Target\":\"" + QUEUE_ARN + "\",\"RoleArn\":\"" + role
                + "\",\"DesiredState\":\"STOPPED\"}";

        user.policy(allow("pipes:CreatePipe", arn + "-other") + "," + passRole(role, PIPES));
        refused(user.rest("pipes").body(create).post(path).then(), "pipes:CreatePipe");
        user.policy(allow("pipes:CreatePipe", arn));
        denied(user.rest("pipes").body(create).post(path).then());
        user.policy(allow("pipes:CreatePipe", arn) + "," + passRole(role, PIPES));
        user.rest("pipes").body(create).post(path).then().statusCode(200);
        cleanup.register(() -> admin("pipes").delete(path));

        String update = "{\"RoleArn\":\"" + other + "\",\"DesiredState\":\"STOPPED\"}";
        user.policy(allow("pipes:UpdatePipe", arn) + "," + passRole(role, PIPES));
        denied(user.rest("pipes").body(update).put(path).then());
        user.policy(allow("pipes:UpdatePipe", arn) + "," + passRole(other, PIPES));
        user.rest("pipes").body(update).put(path).then().statusCode(200);
    }

    @Test
    void aStackNeedsPassRoleOnAServiceRoleTheRequestNames() {
        String role = role("cloudformation");
        User user = user("passrole-stack");
        String stack = "passrole-stack-" + suffix();
        String stacks = allow("cloudformation:CreateStack", "*") + "," + allow("cloudformation:DeleteStack", "*");

        user.policy(stacks);
        denied(createStack(user, stack).formParam("RoleARN", role).post("/").then());
        user.policy(stacks + "," + passRole(role, "cloudformation.amazonaws.com"));
        createStack(user, stack).formParam("RoleARN", role).post("/").then().statusCode(200);
        cleanup.register(() -> admin("cloudformation").formParam("Action", "DeleteStack")
                .formParam("StackName", stack).post("/"));

        // A later operation that names no role reuses the stack's own without passing it.
        user.policy(stacks);
        denied(user.cfn("DeleteStack").formParam("StackName", stack).formParam("RoleARN", role).post("/").then());
        user.cfn("DeleteStack").formParam("StackName", stack).post("/").then().statusCode(200);
    }

    @Test
    void aSelfManagedStackSetPassesTheAdministrationRoleItNamesOrTheDefaultOne() {
        String defaultRole = "arn:aws:iam::" + ACCOUNT + ":role/AWSCloudFormationStackSetAdministrationRole";
        String custom = role("stackset-admin");
        User user = user("passrole-stackset");
        String name = "passrole-stackset-" + suffix();
        String stackSets = allow("cloudformation:CreateStackSet", "*") + ","
                + allow("cloudformation:UpdateStackSet", "*");

        user.policy(stackSets);
        denied(stackSet(user, "CreateStackSet", name).post("/").then());
        user.policy(stackSets + "," + passRole(defaultRole, "cloudformation.amazonaws.com"));
        stackSet(user, "CreateStackSet", name).post("/").then().statusCode(200);
        cleanup.register(() -> admin("cloudformation").formParam("Action", "DeleteStackSet")
                .formParam("StackSetName", name).post("/"));

        // An update naming no administration role passes the default one too, and one naming a role passes it.
        user.policy(stackSets);
        denied(stackSet(user, "UpdateStackSet", name).post("/").then());
        user.policy(stackSets + "," + passRole(defaultRole, "cloudformation.amazonaws.com"));
        denied(stackSet(user, "UpdateStackSet", name).formParam("AdministrationRoleARN", custom).post("/").then());
        user.policy(stackSets + "," + passRole(custom, "cloudformation.amazonaws.com"));
        stackSet(user, "UpdateStackSet", name).formParam("AdministrationRoleARN", custom).post("/").then()
                .statusCode(200);

        // A service-managed StackSet uses no administration role, so none is passed.
        user.policy(stackSets);
        cleanup.register(() -> admin("cloudformation").formParam("Action", "DeleteStackSet")
                .formParam("StackSetName", name + "-org").post("/"));
        stackSet(user, "CreateStackSet", name + "-org").formParam("PermissionModel", "SERVICE_MANAGED").post("/")
                .then().statusCode(not(403)).body(not(containsString("iam:PassRole")));
    }

    /** Requests a Spot Instance, removes it afterwards, and returns the profile ARN it was launched with. */
    private String spotProfileArn(User user, String selector, String profile) {
        String item = "RequestSpotInstancesResponse.spotInstanceRequestSet.item.";
        XmlPath request = spotRequest(user, selector, profile).then().statusCode(200).extract().xmlPath();
        String requestId = request.getString(item + "spotInstanceRequestId");
        cleanup.register(() -> admin("ec2").formParam("Action", "CancelSpotInstanceRequests")
                .formParam("SpotInstanceRequestId.1", requestId).post("/"));
        terminateLater(request.getString(item + "instanceId"));
        return request.getString(item + "launchSpecification.iamInstanceProfile.arn");
    }

    /** A Spot Instance request naming its instance profile by {@code selector}, {@code Arn} or {@code Name}. */
    private static Response spotRequest(User user, String selector, String profile) {
        return user.ec2("RequestSpotInstances").formParam("SpotPrice", "0.05").formParam("InstanceCount", "1")
                .formParam("LaunchSpecification.ImageId", IMAGE).formParam("LaunchSpecification.InstanceType", "t3.micro")
                .formParam("LaunchSpecification.IamInstanceProfile." + selector, profile).post("/");
    }

    private static Response flowLog(User user, String vpcId, String role) {
        return user.ec2("CreateFlowLogs").formParam("ResourceId.1", vpcId).formParam("ResourceType", "VPC")
                .formParam("TrafficType", "ALL").formParam("LogGroupName", "passrole-flow-logs")
                .formParam("DeliverLogsPermissionArn", role).post("/");
    }

    private static String taskDefinition(String family, String taskRole, String executionRole) {
        return """
                {"family":"%s","requiresCompatibilities":["FARGATE"],"networkMode":"awsvpc","cpu":"256","memory":"512",
                 "containerDefinitions":[{"name":"app","image":"nginx:latest","essential":true}]%s%s}"""
                .formatted(family, taskRole == null ? "" : ",\"taskRoleArn\":\"" + taskRole + "\"",
                        executionRole == null ? "" : ",\"executionRoleArn\":\"" + executionRole + "\"");
    }

    /** Registers a task definition with {@code taskRole}, removed afterwards, and returns its family. */
    private String registerTaskDefinition(String taskRole) {
        String family = "passrole-family-" + suffix();
        admin("ecs").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.RegisterTaskDefinition")
                .body(taskDefinition(family, taskRole, null)).post("/").then().statusCode(200);
        deregisterLater(family + ":1");
        return family;
    }

    private void deregisterLater(String taskDefinition) {
        cleanup.register(() -> admin("ecs").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.DeregisterTaskDefinition")
                .body("{\"taskDefinition\":\"" + taskDefinition + "\"}").post("/"));
    }

    /** Creates a cluster, removed afterwards, and returns its name. */
    private String cluster() {
        String name = "passrole-cluster-" + suffix();
        admin("ecs").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.CreateCluster")
                .body("{\"clusterName\":\"" + name + "\"}").post("/").then().statusCode(200);
        cleanup.register(() -> admin("ecs").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.DeleteCluster")
                .body("{\"cluster\":\"" + name + "\"}").post("/"));
        return name;
    }

    private void stopLater(String cluster, String taskArn) {
        cleanup.register(() -> admin("ecs").contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.StopTask")
                .body("{\"cluster\":\"" + cluster + "\",\"task\":\"" + taskArn + "\"}").post("/"));
    }

    private static String runTask(String cluster, String family, String taskRoleOverride) {
        return """
                {"cluster":"%s","taskDefinition":"%s","launchType":"FARGATE","count":1,
                 "networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-default-us-east-1-a"]}}%s}"""
                .formatted(cluster, family, taskRoleOverride == null ? ""
                        : ",\"overrides\":{\"taskRoleArn\":\"" + taskRoleOverride + "\"}");
    }

    private static String service(String cluster, String name, String family) {
        return """
                {"cluster":"%s","serviceName":"%s","taskDefinition":"%s","desiredCount":0,"launchType":"FARGATE",
                 "networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-default-us-east-1-a"]}}}"""
                .formatted(cluster, name, family);
    }

    private static RequestSpecification createStack(User user, String stack) {
        return user.cfn("CreateStack").formParam("StackName", stack).formParam("TemplateBody",
                "{\"Resources\":{\"Q\":{\"Type\":\"AWS::SQS::Queue\",\"Properties\":{\"QueueName\":\"" + stack + "\"}}}}");
    }

    private static RequestSpecification stackSet(User user, String action, String name) {
        return user.cfn(action).formParam("StackSetName", name).formParam("TemplateBody",
                "{\"Resources\":{\"Q\":{\"Type\":\"AWS::SQS::Queue\"}}}");
    }

    private static String roleName(String roleArn) {
        return roleArn.substring(roleArn.lastIndexOf('/') + 1);
    }

    private static void assertPassRoleDenied(Response response) throws IOException {
        JsonNode error = CBOR_MAPPER.readTree(response.then().statusCode(403).extract().asByteArray());
        assertTrue(error.path("message").asText().contains("iam:PassRole"), error.toString());
    }

    private static byte[] gzip(byte[] body) throws IOException {
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(compressed)) {
            out.write(body);
        }
        return compressed.toByteArray();
    }

    /** A REST request refused for the operation's own action, which the message names. */
    private static void refused(ValidatableResponse response, String action) {
        response.statusCode(403).body(containsString(action)).body(not(containsString("iam:PassRole")));
    }

    private static String schedule(String role) {
        return """
                {"ScheduleExpression":"rate(1 hour)","FlexibleTimeWindow":{"Mode":"OFF"},
                 "Target":{"Arn":"%s","RoleArn":"%s"}}""".formatted(QUEUE_ARN, role);
    }

    private static void denied(ValidatableResponse response) {
        response.statusCode(403).body(containsString("iam:PassRole"));
    }

    /** A JSON-protocol service refuses with {@code AccessDeniedException}, which those protocols send as a 400. */
    private static void deniedJson(ValidatableResponse response) {
        response.statusCode(400).body(containsString("AccessDeniedException")).body(containsString("iam:PassRole"));
    }

    private static String allow(String action, String resource) {
        return "{\"Effect\":\"Allow\",\"Action\":\"" + action + "\",\"Resource\":\"" + resource + "\"}";
    }

    private static String passRole(String role, String service) {
        return "{\"Effect\":\"Allow\",\"Action\":\"iam:PassRole\",\"Resource\":\"" + role + "\","
                + "\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"" + service + "\"}}}";
    }

    private String role(String name) {
        return EnforcementFixtures.createRole(cleanup, baseUri.getPort(), ACCOUNT, "/", name + "-" + suffix(),
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\","
                        + "\"Resource\":\"*\"}]}");
    }

    private String instanceProfile(String roleName) {
        String name = "passrole-profile-" + suffix();
        cleanup.register(() -> EnforcementFixtures.removeInstanceProfile(baseUri.getPort(), auth(ADMIN, "iam"), name));
        admin("iam").formParam("Action", "CreateInstanceProfile").formParam("InstanceProfileName", name)
                .post("/").then().statusCode(200);
        admin("iam").formParam("Action", "AddRoleToInstanceProfile").formParam("InstanceProfileName", name)
                .formParam("RoleName", roleName).post("/").then().statusCode(200);
        return name;
    }

    private void terminateLater(String instanceId) {
        cleanup.register(() -> admin("ec2").formParam("Action", "TerminateInstances")
                .formParam("InstanceId.1", instanceId).post("/"));
    }

    private User user(String name) {
        String userName = name + "-" + suffix();
        return new User(userName, EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ADMIN, "iam"),
                userName).accessKeyId());
    }

    private static RequestSpecification admin(String service) {
        return given().header("Authorization", auth(ADMIN, service));
    }

    private static String suffix() {
        return Long.toString(System.nanoTime(), 36);
    }

    /** An IAM user whose one inline policy each test replaces. */
    private record User(String name, String accessKeyId) {

        void policy(String statements) {
            admin("iam").formParam("Action", "PutUserPolicy").formParam("UserName", name)
                    .formParam("PolicyName", "p")
                    .formParam("PolicyDocument", "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}")
                    .post("/").then().statusCode(200);
        }

        RequestSpecification lambda() {
            return given().header("Authorization", auth(accessKeyId, "lambda")).contentType("application/json");
        }

        RequestSpecification ec2(String action) {
            return given().header("Authorization", auth(accessKeyId, "ec2")).formParam("Action", action);
        }

        RequestSpecification ecs(String action) {
            return json("ecs", "AmazonEC2ContainerServiceV20141113." + action);
        }

        RequestSpecification rest(String service) {
            return given().header("Authorization", auth(accessKeyId, service)).contentType("application/json");
        }

        RequestSpecification json(String service, String target) {
            return given().header("Authorization", auth(accessKeyId, service)).header("X-Amz-Target", target)
                    .contentType("application/x-amz-json-1.1");
        }

        /** Step Functions speaks JSON 1.0. */
        RequestSpecification states(String operation) {
            return given().header("Authorization", auth(accessKeyId, "states"))
                    .header("X-Amz-Target", "AWSStepFunctions." + operation).contentType("application/x-amz-json-1.0");
        }

        RequestSpecification cbor(String service) {
            return given().header("Authorization", auth(accessKeyId, service)).header("smithy-protocol", "rpc-v2-cbor")
                    .contentType("application/cbor").accept("application/cbor");
        }

        RequestSpecification cfn(String action) {
            return given().header("Authorization", auth(accessKeyId, "cloudformation")).formParam("Action", action);
        }
    }
}
