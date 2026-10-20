package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The IAM roles a request passes to a service, which the caller also needs {@code iam:PassRole} on.
 * The IAM user guide: "To pass a role (and its permissions) to an AWS service, a user must have
 * permissions to pass the role to the service." AWS's Service Reference names, for each operation
 * that passes one, the service the role goes to, which the check offers as {@code iam:PassedToService};
 * where the request carries the role differs per operation and is listed here.
 *
 * <p>An EC2 request names an instance profile rather than a role, and passes the roles the profile
 * holds. Launching from a launch template passes nothing here: the EC2 user guide warns that a user
 * who can create launch template versions "can potentially update a launch template to pass an IAM
 * role to an instance even if they don't have the iam:PassRole permission", so the role is checked
 * where the template is created.
 *
 * <p>An ECS request that starts tasks from a task definition passes the definition's task role and
 * task execution role: the ECS developer guide has the role EventBridge runs scheduled tasks with
 * hold {@code iam:PassRole} "for each task execution role, task role, or task role override". A role
 * override is checked as well, not instead, since Floci runs a task with its definition's task role.
 * ECS infrastructure roles go to {@code ecs.amazonaws.com} ("To use an ECS infrastructure IAM role,
 * you must grant your user permission to pass the role to Amazon ECS"), task roles to
 * {@code ecs-tasks.amazonaws.com}.
 *
 * <p>A CloudFormation stack's service role is checked where a request names it, and not on later
 * operations that reuse it: CloudFormation "uses this role even if the users don't have permission
 * to pass it". A self-managed StackSet that names no administration role passes the default one:
 * "Even when you don't specify the AdministrationRoleARN parameter, the IAM principal calling
 * CreateStackSet or UpdateStackSet must have iam:PassRole permission for the
 * AWSCloudFormationStackSetAdministrationRole role."
 */
final class PassedRoles {

    private static final Logger LOG = Logger.getLogger(PassedRoles.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** Reads the CBOR bodies the RPC v2 path carries, which name the role in the same member JSON does. */
    private static final ObjectMapper CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    /** An IAM role ARN, the only resource {@code iam:PassRole} acts on. */
    private static final Pattern ROLE_ARN = Pattern.compile("^arn:[a-z0-9-]+:iam::\\d{12}:role/.+");

    private static final String LAMBDA = ServicePrincipals.of("lambda");
    private static final String EC2 = ServicePrincipals.of("ec2");
    private static final String VPC_FLOW_LOGS = ServicePrincipals.of("vpc-flow-logs");
    private static final String ECS = ServicePrincipals.of("ecs");
    private static final String ECS_TASKS = ServicePrincipals.of("ecs-tasks");
    private static final String STATES = ServicePrincipals.of("states");
    private static final String EVENTS = ServicePrincipals.of("events");
    private static final String SCHEDULER = ServicePrincipals.of("scheduler");
    private static final String PIPES = ServicePrincipals.of("pipes");
    private static final String CLOUDFORMATION = ServicePrincipals.of("cloudformation");

    private static final String STACK_SET_ADMINISTRATION_ROLE = "AWSCloudFormationStackSetAdministrationRole";
    private static final String SERVICE_MANAGED = "SERVICE_MANAGED";

    /** A role a request passes, and the service principal it is passed to. */
    record PassedRole(String roleArn, String passedToService) {
    }

    /** What a request names that holds the roles it passes, looked up in the request's account and Region. */
    interface Lookups {

        /** The ARNs of the roles an EC2 instance profile holds, looked up by its name or its ARN. */
        List<String> instanceProfileRoleArns(String profileName, String profileArn);

        /** The task role and task execution role of the ECS task definition {@code reference} names. */
        List<String> taskDefinitionRoles(String reference);

        /** The permission model of the StackSet named {@code stackSetName}; empty when there is none. */
        Optional<String> stackSetPermissionModel(String stackSetName);

        /** The ARN of the role {@code roleName}, a name with any path, names in the request's account. */
        String roleArn(String roleName);
    }

    private PassedRoles() {
    }

    /** The roles a request for {@code action} passes; empty when the operation passes none or the request names none. */
    static List<PassedRole> of(String action, ContainerRequestContext ctx, Lookups lookups) {
        return switch (action) {
            case "lambda:CreateFunction", "lambda:UpdateFunctionConfiguration" -> fromJson(ctx, LAMBDA, "Role");
            case "lambda:CreateWebFunction" ->
                    fromJson(ctx, LAMBDA, "revisionConfig", "serviceConfig", "executionRoleArn");
            case "lambda:CreateWebFunctionRevision" -> fromJson(ctx, LAMBDA, "serviceConfig", "executionRoleArn");
            case "ec2:RunInstances", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation" ->
                    fromInstanceProfile(ctx, lookups, "IamInstanceProfile");
            case "ec2:RequestSpotInstances" ->
                    fromInstanceProfile(ctx, lookups, "LaunchSpecification.IamInstanceProfile");
            case "ec2:CreateLaunchTemplate", "ec2:CreateLaunchTemplateVersion" ->
                    fromInstanceProfile(ctx, lookups, "LaunchTemplateData.IamInstanceProfile");
            case "ec2:CreateFlowLogs" -> fromForm(ctx, VPC_FLOW_LOGS, "DeliverLogsPermissionArn");
            case "ecs:RegisterTaskDefinition" -> ecsTaskDefinition(jsonBody(ctx), lookups);
            case "ecs:RunTask", "ecs:StartTask" -> ecsTask(jsonBody(ctx), lookups);
            case "ecs:CreateService", "ecs:UpdateService" -> ecsService(jsonBody(ctx), lookups);
            case "ecs:CreateTaskSet" -> ecsTaskDefinitionRoles(jsonBody(ctx), lookups);
            case "ecs:CreateCapacityProvider", "ecs:UpdateCapacityProvider" ->
                    ecsRoles(values(jsonBody(ctx), "managedInstancesProvider", "infrastructureRoleArn"), ECS, lookups);
            case "states:CreateStateMachine", "states:UpdateStateMachine" -> fromJson(ctx, STATES, "roleArn");
            case "events:PutRule" -> fromJson(ctx, EVENTS, "RoleArn");
            case "events:PutTargets" -> fromJson(ctx, EVENTS, "Targets", "[]", "RoleArn");
            case "scheduler:CreateSchedule", "scheduler:UpdateSchedule" -> fromJson(ctx, SCHEDULER, "Target", "RoleArn");
            case "pipes:CreatePipe", "pipes:UpdatePipe" -> fromJson(ctx, PIPES, "RoleArn");
            case "cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DeleteStack",
                 "cloudformation:CreateChangeSet", "cloudformation:ContinueUpdateRollback" ->
                    fromForm(ctx, CLOUDFORMATION, "RoleARN");
            case "cloudformation:CreateStackSet", "cloudformation:UpdateStackSet" ->
                    stackSetAdministrationRole(ctx, lookups, "cloudformation:UpdateStackSet".equals(action));
            default -> List.of();
        };
    }

    private static List<PassedRole> ecsTaskDefinition(JsonNode body, Lookups lookups) {
        List<String> roles = new ArrayList<>(values(body, "taskRoleArn"));
        roles.addAll(values(body, "executionRoleArn"));
        return ecsRoles(roles, ECS_TASKS, lookups);
    }

    /** RunTask and StartTask: the task definition's roles and its overrides to the task, and the volumes' infrastructure role. */
    private static List<PassedRole> ecsTask(JsonNode body, Lookups lookups) {
        List<String> taskRoles = new ArrayList<>(taskDefinitionRoles(body, lookups));
        taskRoles.addAll(values(body, "overrides", "taskRoleArn"));
        taskRoles.addAll(values(body, "overrides", "executionRoleArn"));
        List<PassedRole> passed = new ArrayList<>(ecsRoles(taskRoles, ECS_TASKS, lookups));
        passed.addAll(ecsRoles(values(body, "volumeConfigurations", "[]", "managedEBSVolume", "roleArn"), ECS, lookups));
        return passed;
    }

    /** CreateService and UpdateService: the task definition's roles, and the infrastructure roles the service uses. */
    private static List<PassedRole> ecsService(JsonNode body, Lookups lookups) {
        List<String> infrastructure = new ArrayList<>(values(body, "role"));
        infrastructure.addAll(values(body, "loadBalancers", "[]", "advancedConfiguration", "roleArn"));
        infrastructure.addAll(values(body, "deploymentConfiguration", "lifecycleHooks", "[]", "roleArn"));
        infrastructure.addAll(values(body, "serviceConnectConfiguration", "services", "[]", "tls", "roleArn"));
        infrastructure.addAll(values(body, "volumeConfigurations", "[]", "managedEBSVolume", "roleArn"));
        infrastructure.addAll(values(body, "vpcLatticeConfigurations", "[]", "roleArn"));
        List<PassedRole> passed = new ArrayList<>(ecsTaskDefinitionRoles(body, lookups));
        passed.addAll(ecsRoles(infrastructure, ECS, lookups));
        return passed;
    }

    private static List<PassedRole> ecsTaskDefinitionRoles(JsonNode body, Lookups lookups) {
        return ecsRoles(taskDefinitionRoles(body, lookups), ECS_TASKS, lookups);
    }

    /** The roles of the task definition the request names; none when it names none. */
    private static List<String> taskDefinitionRoles(JsonNode body, Lookups lookups) {
        List<String> reference = values(body, "taskDefinition");
        return reference.isEmpty() || reference.get(0).isBlank()
                ? List.of() : lookups.taskDefinitionRoles(reference.get(0));
    }

    /**
     * ECS takes a role by its name as well as by its ARN ({@code taskRoleArn} is "The short name or
     * full Amazon Resource Name (ARN) of the IAM role"), and a name is the role in the request's account.
     */
    private static List<PassedRole> ecsRoles(List<String> roles, String service, Lookups lookups) {
        List<String> arns = new ArrayList<>();
        for (String role : roles) {
            if (!role.isBlank()) {
                arns.add(role.startsWith("arn:") ? role : lookups.roleArn(role));
            }
        }
        return passed(arns, service);
    }

    /**
     * The administration role a StackSet operation passes: the one it names, or else, unless the
     * StackSet uses service-managed permissions, the default one. An update goes by the StackSet's
     * own permission model, which Floci keeps whatever the request names, and one of a StackSet that
     * does not exist passes nothing.
     */
    private static List<PassedRole> stackSetAdministrationRole(ContainerRequestContext ctx, Lookups lookups,
                                                               boolean update) {
        Map<String, String> form = IamConditionContextResolver.formParameters(ctx);
        String named = blankToNull(form.get("AdministrationRoleARN"));
        if (named != null) {
            return passed(List.of(named), CLOUDFORMATION);
        }
        String model = blankToNull(form.get("PermissionModel"));
        if (update) {
            String name = blankToNull(form.get("StackSetName"));
            Optional<String> stored = name == null ? Optional.empty() : lookups.stackSetPermissionModel(name);
            if (stored.isEmpty()) {
                return List.of();
            }
            model = stored.get();
        }
        return SERVICE_MANAGED.equals(model)
                ? List.of() : passed(List.of(lookups.roleArn(STACK_SET_ADMINISTRATION_ROLE)), CLOUDFORMATION);
    }

    private static List<PassedRole> fromJson(ContainerRequestContext ctx, String service, String... path) {
        return passed(values(jsonBody(ctx), path), service);
    }

    /** The strings at {@code path} in {@code node}, where a {@code []} step takes each element of an array. */
    private static List<String> values(JsonNode node, String... path) {
        List<String> found = new ArrayList<>();
        collect(node, path, 0, found);
        return found;
    }

    private static void collect(JsonNode node, String[] path, int step, List<String> found) {
        if (node == null) {
            return;
        }
        if (step == path.length) {
            if (node.isTextual()) {
                found.add(node.asText());
            }
            return;
        }
        if ("[]".equals(path[step])) {
            if (node.isArray()) {
                for (JsonNode element : node) {
                    collect(element, path, step + 1, found);
                }
            }
            return;
        }
        collect(node.get(path[step]), path, step + 1, found);
    }

    private static List<PassedRole> fromForm(ContainerRequestContext ctx, String service, String parameter) {
        String roleArn = IamConditionContextResolver.formParameters(ctx).get(parameter);
        return roleArn == null ? List.of() : passed(List.of(roleArn), service);
    }

    /** The roles of the instance profile named by {@code prefix}.Name or {@code prefix}.Arn. */
    private static List<PassedRole> fromInstanceProfile(ContainerRequestContext ctx, Lookups lookups, String prefix) {
        Map<String, String> form = IamConditionContextResolver.formParameters(ctx);
        String name = blankToNull(form.get(prefix + ".Name"));
        String arn = blankToNull(form.get(prefix + ".Arn"));
        if (name == null && arn == null) {
            return List.of();
        }
        return passed(lookups.instanceProfileRoleArns(name, arn), EC2);
    }

    /** The roles that are IAM role ARNs; anything else is left for the operation to refuse. */
    private static List<PassedRole> passed(List<String> roleArns, String service) {
        List<PassedRole> passed = new ArrayList<>();
        for (String roleArn : roleArns) {
            if (roleArn != null && ROLE_ARN.matcher(roleArn).matches()) {
                passed.add(new PassedRole(roleArn, service));
            }
        }
        return passed;
    }

    /**
     * The request's JSON or CBOR body, read once and kept where the other request readers look for it.
     * A gzip-encoded body is decompressed first, as {@code AwsJsonCborController} decompresses it before
     * running the request.
     */
    private static JsonNode jsonBody(ContainerRequestContext ctx) {
        if (ctx.getProperty(IamConditionContextResolver.BUFFERED_JSON_BODY) instanceof JsonNode cached) {
            return cached;
        }
        byte[] body = IamConditionContextResolver.bufferEntity(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            String encoding = ctx.getHeaderString(HttpHeaders.CONTENT_ENCODING);
            if (encoding != null && AwsJsonCborController.isGZipped(List.of(encoding))) {
                body = AwsJsonCborController.decodeBody(body);
            }
            JsonNode node = (isCbor(ctx.getMediaType()) ? CBOR_MAPPER : MAPPER).readTree(body);
            ctx.setProperty(IamConditionContextResolver.BUFFERED_JSON_BODY, node);
            return node;
        } catch (IOException | AwsException e) {
            // The operation refuses a body it cannot decompress or parse itself; nothing here names a role.
            LOG.debugv(e, "Request body cannot be read, so it passes no role");
            return null;
        }
    }

    /** Both CBOR content types arrive as {@code application/cbor}, as {@code ResourceArnBuilder} reads them. */
    private static boolean isCbor(MediaType mediaType) {
        return mediaType != null
                && "application".equalsIgnoreCase(mediaType.getType())
                && ("cbor".equalsIgnoreCase(mediaType.getSubtype())
                        || "x-amz-cbor-1.1".equalsIgnoreCase(mediaType.getSubtype()));
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
