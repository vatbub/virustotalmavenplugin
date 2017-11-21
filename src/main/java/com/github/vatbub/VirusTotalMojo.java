package com.github.vatbub;

/*-
 * #%L
 * virustotal-maven-plugin Maven Mojo
 * %%
 * Copyright (C) 2016 - 2017 Frederik Kammel
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Goal which sends all project artifacts to VirusTotal.
 */
@Mojo(name = "scan", defaultPhase = LifecyclePhase.VERIFY, requiresOnline = true)
public class VirusTotalMojo extends AbstractMojo {
    /**
     * The VirusTotal api key
     */
    @Parameter(property = "virustotal.apiKey", required = true)
    private String apiKey;

    /**
     * Specifies if the build shall fail if any artifact is marked as a virus.
     */
    @Parameter(property = "virustotal.failIfVirus", defaultValue = "false")
    private boolean failIfVirus;

    /**
     * Specifies whether requests to the virus total api shall be slowed down to avoid {@code QuotaExceededException}s
     */
    @Parameter(property = "virustotal.slowRequestsDown", defaultValue = "true")
    private boolean slowRequestsDown;

    /**
     * If true, skips the scan
     */
    @Parameter(property = "virustotal.skipScan", defaultValue = "false")
    private boolean skipScan;

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    private void checkQuotaExceededException() throws MojoExecutionException {
        getLog().warn("Request rate of 4 requests per minute exceeded, waiting two minutes...");
        try {
            Thread.sleep(120000);
        } catch (InterruptedException e1) {
            throw new MojoExecutionException("Thread was interrupted while sleeping", e1);
        }
    }

    private void doSlowDown() throws MojoExecutionException {
        if (slowRequestsDown) {
            try {
                getLog().info("Waiting a minute to avoid a QuotaExceededException... (Set slowRequestsDown to false in the plugin config if you wish to avoid this behaviour)");
                Thread.sleep(60000);
            } catch (InterruptedException e) {
                throw new MojoExecutionException("Thread was interruped", e);
            }
        }
    }

    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skipScan) {
            getLog().info("Skipping the Virus Total scan");
            return;
        }

        try {
            List<Artifact> artifactsToCheck = new ArrayList<>();
            //noinspection unchecked
            artifactsToCheck.addAll(project.getAttachedArtifacts());
            artifactsToCheck.add(project.getArtifact());

            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apiKey);
            VirustotalPublicV2 virustotalPublicV2 = new VirustotalPublicV2Impl();

            for (Artifact artifact : artifactsToCheck) {
                if (artifact==null || artifact.getFile()==null)
                    continue;

                doSlowDown();
                ScanInfo scanInfo;
                while (true) {
                    getLog().info("Scanning file " + artifact.getFile().getAbsolutePath());
                    try {
                        scanInfo = virustotalPublicV2.scanFile(artifact.getFile());
                        getLog().info("Detailed scan result available at: " + scanInfo.getPermalink());
                        break; // no exception
                    } catch (QuotaExceededException e) {
                        checkQuotaExceededException();
                    }
                }

                FileScanReport report = null;
                doSlowDown();

                do {
                    try {
                        getLog().debug("Waiting for the scan to complete...");
                        report = virustotalPublicV2.getScanReport(scanInfo.getResource());
                    } catch (QuotaExceededException e) {
                        checkQuotaExceededException();
                    }
                } while (report == null || report.getPositives() == null);

                getLog().info("Total number of anti virus software that scanned this artifact: " + report.getTotal());

                if (report.getPositives() > 0) {
                    String failureString = report.getPositives() + " marked the artifact " + artifact.getFile().getAbsolutePath() + " as a virus.";
                    if (failIfVirus) {
                        throw new MojoFailureException(failureString);
                    } else {
                        getLog().warn(failureString);
                    }
                }
            }
        } catch (APIKeyNotFoundException e) {
            throw new MojoExecutionException("API Key not found", e);
        } catch (IOException e) {
            throw new MojoExecutionException("Unable to scan the artifacts", e);
        } catch (UnauthorizedAccessException e) {
            throw new MojoExecutionException("API key not valid", e);
        }
    }
}
