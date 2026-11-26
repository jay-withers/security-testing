// Shared test fixtures.

import type { Container, Row } from "../src/scan.ts";

/** A Resource Graph row for one container app. */
export function row(
  name = "app",
  fqdn = "app.example.azurecontainerapps.io",
  tags: Record<string, string> | null = null,
  extra: Partial<Row> = {},
): Row {
  return {
    id: `/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/${name}`,
    name,
    resourceGroup: "rg",
    subscriptionId: "sub",
    fqdn,
    runningStatus: "Running",
    tags,
    ...extra,
  };
}

/** A fake blob container: name -> [bytes, content type]. */
export class FakeContainer implements Container {
  blobs = new Map<string, [Buffer, string | undefined]>();

  constructor(json: Record<string, unknown> = {}) {
    for (const [name, value] of Object.entries(json)) {
      this.blobs.set(name, [Buffer.from(JSON.stringify(value)), "application/json"]);
    }
  }

  getBlockBlobClient(name: string) {
    return {
      uploadData: async (data: Buffer, options?: { blobHTTPHeaders?: { blobContentType?: string } }) => {
        this.blobs.set(name, [data, options?.blobHTTPHeaders?.blobContentType]);
      },
    };
  }

  getBlobClient(name: string) {
    return {
      downloadToBuffer: async () => {
        const blob = this.blobs.get(name);
        if (!blob)
          throw Object.assign(new Error(`${name} not found`), {
            name: "RestError",
            statusCode: 404,
          });
        return blob[0];
      },
    };
  }

  async *listBlobsFlat() {
    for (const name of this.blobs.keys()) yield { name };
  }

  text(name: string): string | undefined {
    return this.blobs.get(name)?.[0].toString("utf8");
  }
}
