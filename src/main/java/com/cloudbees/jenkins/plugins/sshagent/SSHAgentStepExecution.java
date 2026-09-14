package com.cloudbees.jenkins.plugins.sshagent;

import com.cloudbees.jenkins.plugins.sshagent.exec.ExecRemoteAgent;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Computer;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.workflow.steps.BodyExecutionCallback;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;
import org.jenkinsci.plugins.workflow.steps.GeneralNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

final class SSHAgentStepExecution extends GeneralNonBlockingStepExecution {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(SSHAgentStepExecution.class.getName());

    /**
     * Invoked on the background thread immediately before {@code ssh-agent} is launched.
     * Tests use this to prove {@link #start()} returned without blocking the CPS VM.
     */
    static volatile Runnable beforeAgentStart;

    private transient SSHAgentStep step;

    private ExecRemoteAgent agent;

    SSHAgentStepExecution(SSHAgentStep step, StepContext context) {
        super(context);
        this.step = step;
    }

    @Override
    public boolean start() throws Exception {
        run(this::doStart);
        return false;
    }

    private void doStart() throws Exception {
        StepContext context = getContext();
        initRemoteAgent();
        context.newBodyInvoker().
                withContext(EnvironmentExpander.merge(context.get(EnvironmentExpander.class), new ExpanderImpl(this))).
                withCallback(new Callback()).start();
    }

    @Override
    public void stop(@NonNull Throwable cause) throws Exception {
        super.stop(cause);
        stopAgentAsync(cause);
    }

    private void stopAgent() throws Exception {
        if (agent != null) {
            TaskListener listener = getContext().get(TaskListener.class);
            Launcher launcher = getContext().get(Launcher.class);
            if (listener != null && launcher != null) {
                agent.stop(launcher, listener);
                listener.getLogger().println(Messages.SSHAgentBuildWrapper_Stopped());
            }
        }
    }

    private void stopAgentAsync(Throwable cause) {
        if (agent == null) {
            return;
        }
        Authentication auth = Jenkins.getAuthentication2();
        Computer.threadPoolForRemoting.submit(() -> {
            try (ACLContext ignored = ACL.as2(auth)) {
                stopAgent();
            } catch (Exception x) {
                if (cause != null) {
                    cause.addSuppressed(x);
                }
                LOGGER.log(Level.WARNING, "failed to stop ssh-agent", x);
            }
        });
    }

    private class Callback extends BodyExecutionCallback {

        private static final long serialVersionUID = 1L;

        @Override
        public void onSuccess(StepContext context, Object result) {
            run(() -> {
                try {
                    stopAgent();
                } catch (Exception x) {
                    context.onFailure(x);
                    return;
                }
                context.onSuccess(result);
            });
        }

        @Override
        public void onFailure(StepContext context, Throwable t) {
            run(() -> {
                try {
                    stopAgent();
                } catch (Exception x) {
                    t.addSuppressed(x);
                }
                context.onFailure(t);
            });
        }

    }

    private static final class ExpanderImpl extends EnvironmentExpander {

        private static final long serialVersionUID = 1L;

        private final SSHAgentStepExecution execution;

        ExpanderImpl(SSHAgentStepExecution execution) {
            this.execution = execution;
        }

        @Override
        public void expand(EnvVars env) throws IOException, InterruptedException {
            env.overrideAll(execution.agent.getEnv());
        }
    }

    /**
     * Initializes a SSH Agent.
     *
     * @throws IOException
     */
    private void initRemoteAgent() throws IOException, InterruptedException {
        Launcher launcher = getContext().get(Launcher.class);
        TaskListener listener = getContext().get(TaskListener.class);
        Run<?, ?> build = getContext().get(Run.class);
        FilePath workspace = getContext().get(FilePath.class);
        List<SSHUserPrivateKey> userPrivateKeys = new ArrayList<>();
        for (String id : new LinkedHashSet<>(step.getCredentials())) {
            final SSHUserPrivateKey c = CredentialsProvider.findCredentialById(id, SSHUserPrivateKey.class, build);
            CredentialsProvider.track(build, c);
            if (c == null && !step.isIgnoreMissing()) {
                throw new AbortException(Messages.SSHAgentBuildWrapper_CredentialsNotFound(id));
            }
            if (c != null && !userPrivateKeys.contains(c)) {
                userPrivateKeys.add(c);
            }
        }
        for (SSHUserPrivateKey userPrivateKey : userPrivateKeys) {
            listener.getLogger().println(Messages.SSHAgentBuildWrapper_UsingCredentials(SSHAgentBuildWrapper.description(userPrivateKey)));
        }

        Runnable hook = beforeAgentStart;
        if (hook != null) {
            hook.run();
        }

        agent = new ExecRemoteAgent(launcher, listener);

        for (SSHUserPrivateKey userPrivateKey : userPrivateKeys) {
            final Secret passphrase = userPrivateKey.getPassphrase();
            final String effectivePassphrase = passphrase == null ? null : passphrase.getPlainText();
            for (String privateKey : userPrivateKey.getPrivateKeys()) {
                agent.addIdentity(privateKey, effectivePassphrase, SSHAgentBuildWrapper.description(userPrivateKey), workspace, launcher, listener);
            }
        }

        listener.getLogger().println(Messages.SSHAgentBuildWrapper_Started());
    }

}
