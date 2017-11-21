# VirusTotal Maven Plugin
This plugin submits the maven artifacts of a maven build to [VirusTotal](https://www.virustotal.com/)  
and scans them there with over 60 anti virus software packages to see 
if any of the artifacts is recognized as a virus.

## Why do you need that?
When you do a maven build, you also have access to the source code of the application you're building, 
that means that you know that the program is not a virus. 
However, sometimes it might be a good idea to show to customers a proof 
that your application is not a virus. This plugin creates that proof for you.

## Getting started
### The VirusTotal API Key
1. Head over to [virustotal.com](https://www.virustotal.com/) and sign in or create an account if you don't already have one.
2. Click your profile picture and go to [Settings -> API Key](https://www.virustotal.com/#/settings/apikey) (or just click the link ;) ) and copy your API key. 
### Configuration
Now, add the following to your `pom.xml`:

```xml
<build>
    <plugins>
        <plugin>
            <groupId>com.github.vatbub</groupId>
            <artifactId>virustotal-maven-plugin</artifactId>
            <version>1.1</version>
            <executions>
                <execution>
                    <phase>verify</phase>
                    <goals>
                        <goal>scan</goal>
                    </goals>
                    <configuration>
                        <apiKey>yourApiKey</apiKey>
                    </configuration>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

Now, run `mvn clean verify` in your project and it will be uploaded to virus total. The plugin will output the URLs to the detailed reports for you to check out and to send to your customers as a proof that you don't sell viruses.

# Advanced configuration
## Skip a scan
If you wish to skip a scan for a particular build, add `-Dvirustotal.skipScan=true` to the maven command line call.
## Make a build fail if VirusTotal considers an artifact a virus
By default, a warning message will be put into the log if at least one artifact was recognized as a virus by at least one anti virus software.
If you wish to make the build fail instead, you can add the following to the plugin configuration:

`<failIfVirus>true</failIfVirus>`

# The API request rate limit
For standard users, the VirusTotal API limits requests to 4 requests per minute per API key.
Due to the strange way that VirusTotal counts requests, a build with only a single artifact will cause the limit to be exceeded.
The plugin therefore waits one minute between requests to avoid exceptions.
If a `QuotaExceededException` occurs anyway, the plugin waits even two more minutes.
If you have a larger amount of files to scan, you can request a private api key at VirusTotal in your [API Key settings](https://www.virustotal.com/#/settings/apikey) with a higher request rate limit.
In that case, add `<slowRequestsDown>false</slowRequestsDown>` to the plugin configuration to disable this behaviour.

*Note: Even with `slowRequestsDown` set to `false`, the plugin will wait two minutes if the request rate limit is exceeded.*

# Legal stuff
This plugin is licensed under the *APACHE LICENSE v2* (see `LICENSE.txt` for details).

The name *VirusTotal* is and will remain the exclusive property of VirusTotal and its licensors. 

Usage of the VirusTotal API (an thus the usage of this plugin) is subject to the [VirusTotal Terms of Service](https://support.virustotal.com/hc/en-us/articles/115002145529-Terms-of-Service), the [VirusTotal Best practices](https://support.virustotal.com/hc/en-us/articles/115002178485-Best-practices) and the [VirusTotal Privacy Policy](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy).
