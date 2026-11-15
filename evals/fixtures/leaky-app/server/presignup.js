// Cognito PreSignUp trigger
exports.handler = async (event) => {
  const attrs = event.request.userAttributes;
  const domain = (attrs.email || "").split("@")[1];
  const tenant = await lookupTenant(attrs["custom:tenantId"]);
  if (!tenant) throw new Error(`Invalid tenant domain: ${domain}`);
  if (tenant.domain !== domain) throw new Error("tenantId does not match tenant domain");
  if (attrs["custom:isAdmin"] && typeof attrs["custom:isAdmin"] !== "string") {
    throw new Error("Type for attribute {custom:isAdmin} could not be determined");
  }
  event.response.autoConfirmUser = true;
  return event;
};

async function lookupTenant(id) {
  const tenants = require("./tenants.json");
  return tenants[id];
}
