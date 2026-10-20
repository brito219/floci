package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import io.github.hectorvent.floci.core.common.PassedRoles.PassedRole;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Where each operation carries the roles it passes, and the service each goes to. The enforcement
 * of the check is covered by {@code IamPassRoleEnforcementIntegrationTest}; this covers the table.
 */
class PassedRolesTest {

    private static final String ROLES = "arn:aws:iam::111122223333:role/";
    private static final String ECS = "ecs.amazonaws.com";
    private static final String ECS_TASKS = "ecs-tasks.amazonaws.com";
    private static final String CLOUDFORMATION = "cloudformation.amazonaws.com";
    private static final String DEFAULT_ADMINISTRATION = ROLES + "AWSCloudFormationStackSetAdministrationRole";

    /** A task definition {@code web:3} holding a task role by ARN and an execution role by name, and two StackSets. */
    private static final PassedRoles.Lookups LOOKUPS = new PassedRoles.Lookups() {
        @Override
        public List<String> instanceProfileRoleArns(String profileName, String profileArn) {
            return List.of();
        }

        @Override
        public List<String> taskDefinitionRoles(String reference) {
            return "web:3".equals(reference) ? List.of(ROLES + "web-task", "web-execution") : List.of();
        }

        @Override
        public Optional<String> stackSetPermissionModel(String stackSetName) {
            return switch (stackSetName) {
                case "own-set" -> Optional.of("SELF_MANAGED");
                case "org-set" -> Optional.of("SERVICE_MANAGED");
                default -> Optional.empty();
            };
        }

        @Override
        public String roleArn(String roleName) {
            return ROLES + roleName;
        }
    };

    @Test
    void aTaskDefinitionPassesItsTaskAndExecutionRolesToEcsTasksByNameOrArn() {
        assertEquals(List.of(passed("app", ECS_TASKS), passed("exec", ECS_TASKS)),
                PassedRoles.of("ecs:RegisterTaskDefinition",
                        json("{\"taskRoleArn\":\"app\",\"executionRoleArn\":\"" + ROLES + "exec\"}"), LOOKUPS));
    }

    @Test
    void aTaskPassesItsDefinitionsRolesItsOverridesAndItsVolumesInfrastructureRole() {
        String body = """
                {"taskDefinition":"web:3","overrides":{"taskRoleArn":"%1$sover-task","executionRoleArn":"%1$sover-exec"},
                 "volumeConfigurations":[{"name":"a","managedEBSVolume":{"roleArn":"%1$sebs"}}]}"""
                .formatted(ROLES);
        List<PassedRole> expected = List.of(passed("web-task", ECS_TASKS), passed("web-execution", ECS_TASKS),
                passed("over-task", ECS_TASKS), passed("over-exec", ECS_TASKS), passed("ebs", ECS));

        assertEquals(expected, PassedRoles.of("ecs:RunTask", json(body), LOOKUPS));
        assertEquals(expected, PassedRoles.of("ecs:StartTask", json(body), LOOKUPS));
    }

    @Test
    void aTaskDefinitionThatDoesNotExistPassesNothing() {
        assertEquals(List.of(), PassedRoles.of("ecs:RunTask", json("{\"taskDefinition\":\"missing\"}"), LOOKUPS));
    }

    @Test
    void aServicePassesItsDefinitionsRolesAndEachInfrastructureRole() {
        String body = """
                {"taskDefinition":"web:3","role":"legacy",
                 "loadBalancers":[{"advancedConfiguration":{"roleArn":"%1$slb"}}],
                 "deploymentConfiguration":{"lifecycleHooks":[{"roleArn":"%1$shook"}]},
                 "serviceConnectConfiguration":{"services":[{"tls":{"roleArn":"%1$stls"}}]},
                 "volumeConfigurations":[{"managedEBSVolume":{"roleArn":"%1$sebs"}}],
                 "vpcLatticeConfigurations":[{"roleArn":"%1$slattice"}]}"""
                .formatted(ROLES);
        List<PassedRole> expected = List.of(passed("web-task", ECS_TASKS), passed("web-execution", ECS_TASKS),
                passed("legacy", ECS), passed("lb", ECS), passed("hook", ECS), passed("tls", ECS),
                passed("ebs", ECS), passed("lattice", ECS));

        assertEquals(expected, PassedRoles.of("ecs:CreateService", json(body), LOOKUPS));
        assertEquals(expected, PassedRoles.of("ecs:UpdateService", json(body), LOOKUPS));
        // An update that keeps its task definition passes only the roles it names.
        assertEquals(List.of(passed("lattice", ECS)), PassedRoles.of("ecs:UpdateService",
                json("{\"vpcLatticeConfigurations\":[{\"roleArn\":\"" + ROLES + "lattice\"}]}"), LOOKUPS));
    }

    @Test
    void aTaskSetPassesItsDefinitionsRolesOnly() {
        // The Service Reference gives CreateTaskSet ecs-tasks.amazonaws.com alone.
        String body = "{\"taskDefinition\":\"web:3\",\"loadBalancers\":[{\"advancedConfiguration\":{\"roleArn\":\""
                + ROLES + "lb\"}}]}";
        assertEquals(List.of(passed("web-task", ECS_TASKS), passed("web-execution", ECS_TASKS)),
                PassedRoles.of("ecs:CreateTaskSet", json(body), LOOKUPS));
    }

    @Test
    void aManagedInstancesProviderPassesItsInfrastructureRoleToEcs() {
        String body = "{\"managedInstancesProvider\":{\"infrastructureRoleArn\":\"" + ROLES + "infra\"}}";
        assertEquals(List.of(passed("infra", ECS)), PassedRoles.of("ecs:CreateCapacityProvider", json(body), LOOKUPS));
        assertEquals(List.of(passed("infra", ECS)), PassedRoles.of("ecs:UpdateCapacityProvider", json(body), LOOKUPS));
    }

    @Test
    void stepFunctionsAndEventBridgePassTheRoleTheyName() throws IOException {
        String role = "{\"roleArn\":\"" + ROLES + "sm\"}";
        assertEquals(List.of(passed("sm", "states.amazonaws.com")),
                PassedRoles.of("states:CreateStateMachine", json(role), LOOKUPS));
        assertEquals(List.of(passed("sm", "states.amazonaws.com")),
                PassedRoles.of("states:UpdateStateMachine", cbor(role), LOOKUPS));
        assertEquals(List.of(passed("sm", "states.amazonaws.com")),
                PassedRoles.of("states:CreateStateMachine", gzippedCbor(role), LOOKUPS));
        assertEquals(List.of(passed("rule", "events.amazonaws.com")),
                PassedRoles.of("events:PutRule", json("{\"RoleArn\":\"" + ROLES + "rule\"}"), LOOKUPS));
        assertEquals(List.of(passed("one", "events.amazonaws.com"), passed("two", "events.amazonaws.com")),
                PassedRoles.of("events:PutTargets", json("{\"Targets\":[{\"RoleArn\":\"" + ROLES + "one\"},{},"
                        + "{\"RoleArn\":\"" + ROLES + "two\"}]}"), LOOKUPS));
    }

    @Test
    void schedulerAndPipesPassTheRoleTheyName() {
        String target = "{\"Target\":{\"RoleArn\":\"" + ROLES + "schedule\"}}";
        assertEquals(List.of(passed("schedule", "scheduler.amazonaws.com")),
                PassedRoles.of("scheduler:CreateSchedule", json(target), LOOKUPS));
        assertEquals(List.of(passed("schedule", "scheduler.amazonaws.com")),
                PassedRoles.of("scheduler:UpdateSchedule", json(target), LOOKUPS));
        String pipe = "{\"RoleArn\":\"" + ROLES + "pipe\"}";
        assertEquals(List.of(passed("pipe", "pipes.amazonaws.com")), PassedRoles.of("pipes:CreatePipe", json(pipe), LOOKUPS));
        assertEquals(List.of(passed("pipe", "pipes.amazonaws.com")), PassedRoles.of("pipes:UpdatePipe", json(pipe), LOOKUPS));
    }

    @Test
    void outsideEcsOnlyARoleArnIsPassed() {
        assertEquals(List.of(), PassedRoles.of("states:CreateStateMachine", json("{\"roleArn\":\"sm\"}"), LOOKUPS));
    }

    @Test
    void aStackOperationPassesTheServiceRoleItNames() {
        for (String action : List.of("CreateStack", "UpdateStack", "DeleteStack", "CreateChangeSet",
                "ContinueUpdateRollback")) {
            assertEquals(List.of(passed("stack", CLOUDFORMATION)),
                    PassedRoles.of("cloudformation:" + action, form("RoleARN=" + ROLES + "stack"), LOOKUPS), action);
            assertEquals(List.of(), PassedRoles.of("cloudformation:" + action, form("StackName=s"), LOOKUPS), action);
        }
    }

    @Test
    void aStackSetPassesTheAdministrationRoleItNamesOrTheDefaultOneWhenSelfManaged() {
        PassedRole defaultRole = new PassedRole(DEFAULT_ADMINISTRATION, CLOUDFORMATION);
        assertEquals(List.of(defaultRole), PassedRoles.of("cloudformation:CreateStackSet", form("StackSetName=new"), LOOKUPS));
        assertEquals(List.of(), PassedRoles.of("cloudformation:CreateStackSet",
                form("StackSetName=new&PermissionModel=SERVICE_MANAGED"), LOOKUPS));
        assertEquals(List.of(passed("admin", CLOUDFORMATION)), PassedRoles.of("cloudformation:CreateStackSet",
                form("StackSetName=new&AdministrationRoleARN=" + ROLES + "admin"), LOOKUPS));

        // An update goes by the StackSet's own permission model, which a PermissionModel it names doesn't change.
        assertEquals(List.of(defaultRole), PassedRoles.of("cloudformation:UpdateStackSet", form("StackSetName=own-set"), LOOKUPS));
        assertEquals(List.of(defaultRole), PassedRoles.of("cloudformation:UpdateStackSet",
                form("StackSetName=own-set&PermissionModel=SERVICE_MANAGED"), LOOKUPS));
        assertEquals(List.of(), PassedRoles.of("cloudformation:UpdateStackSet", form("StackSetName=org-set"), LOOKUPS));
        assertEquals(List.of(), PassedRoles.of("cloudformation:UpdateStackSet",
                form("StackSetName=org-set&PermissionModel=SELF_MANAGED"), LOOKUPS));
        assertEquals(List.of(), PassedRoles.of("cloudformation:UpdateStackSet", form("StackSetName=missing"), LOOKUPS));
        assertEquals(List.of(passed("admin", CLOUDFORMATION)), PassedRoles.of("cloudformation:UpdateStackSet",
                form("StackSetName=org-set&AdministrationRoleARN=" + ROLES + "admin"), LOOKUPS));
    }

    private static PassedRole passed(String roleName, String service) {
        return new PassedRole(ROLES + roleName, service);
    }

    private static ContainerRequestContext json(String body) {
        return request("application/x-amz-json-1.1", body.getBytes(StandardCharsets.UTF_8));
    }

    private static ContainerRequestContext cbor(String body) throws IOException {
        return request("application/cbor",
                new ObjectMapper(new CBORFactory()).writeValueAsBytes(new ObjectMapper().readTree(body)));
    }

    private static ContainerRequestContext gzippedCbor(String body) throws IOException {
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(compressed)) {
            out.write(new ObjectMapper(new CBORFactory()).writeValueAsBytes(new ObjectMapper().readTree(body)));
        }
        ContainerRequestContext request = request("application/cbor", compressed.toByteArray());
        when(request.getHeaderString("Content-Encoding")).thenReturn("gzip");
        return request;
    }

    private static ContainerRequestContext form(String body) {
        return request("application/x-www-form-urlencoded", body.getBytes(StandardCharsets.UTF_8));
    }

    private static ContainerRequestContext request(String mediaType, byte[] body) {
        ContainerRequestContext request = mock(ContainerRequestContext.class);
        when(request.getMediaType()).thenReturn(MediaType.valueOf(mediaType));
        when(request.getEntityStream()).thenAnswer(invocation -> new ByteArrayInputStream(body));
        return request;
    }
}
