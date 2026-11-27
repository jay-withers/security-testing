/**
 * The wiring: real Azure clients behind the seams the other modules take.
 *
 * Deliberately untested and left out of coverage (vitest.config.ts), as
 * the Python scanner's main() was: everything here only constructs SDK clients, and a
 * test of it could only assert mocks. Every decision they feed is tested
 * through the seams instead.
 */

import { ResourceGraphClient } from "@azure/arm-resourcegraph";
import { DefaultAzureCredential, type TokenCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import { ContainerClient } from "@azure/storage-blob";

import type { Commands } from "./cli.ts";
import { sendDigest } from "./digest.ts";
import { getSecret, send, type Secret } from "./mailer.ts";
import { runFromEnv } from "./scan.ts";
import { run as selfcheck } from "./selfcheck.ts";

// AZURE_CLIENT_ID picks the job's user-assigned managed identity.
function credential(): TokenCredential {
  return new DefaultAzureCredential();
}

function secrets(cred: TokenCredential): Secret {
  return (name) => getSecret(name, (uri) => new SecretClient(uri, cred));
}

export const commands: Commands = {
  async scan() {
    return runFromEnv((config) => {
      const cred = credential();
      const secret = secrets(cred);
      return {
        resourceGraph: new ResourceGraphClient(cred),
        container: new ContainerClient(config.containerUrl, cred),
        sendDigest: (container, prefix, sender) =>
          sendDigest(container, prefix, sender, (subject, html, text, from) =>
            send(subject, html, text, from, secret),
          ),
      };
    });
  },
  async selfcheck() {
    const cred = credential();
    return selfcheck({
      resourceGraph: () => new ResourceGraphClient(cred),
      reportContainer: (url) => new ContainerClient(url, cred).getProperties(),
      secret: secrets(cred),
    });
  },
};
