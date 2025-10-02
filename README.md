# Get started
## Have a configured Identity Provider
See the Auth0 userguide. 

## Create config files for the various services
Reminder: 
1. Your authority = the domain of your Auth0 Bar Application,
e.g. opa-demo-splynter.eu.auth0.com;
2. Your clientid = the Client ID of your Auth0 Bar Application,
e.g. AZbplMtgWHVthjRBiEM50Lgqd0nfJg;
3. Your audience = the Identifier of your Auth0 API,
e.g. bar-auth0-api.

### For the SPA
Create a `settings.js` file in the root of the SPA folder and fill in the `<blanks>`.

```
import { Log, UserManager} from "oidc-client-ts";

Log.setLogger(console);
Log.setLevel(Log.INFO);

const url = window.location.origin + "";

export const settings = {
    authority: "<your authority>",
    client_id: "<your clientid>",
    redirect_uri: url + "/callback.html",
    post_logout_redirect_uri: url + "/index.html",
    response_type: "code",
    scope: "openid email roles",

    response_mode: "query",

    filterProtocolClaims: true,
    extraQueryParams: {
        audience: "<your audience>",
    },
    api_bar_uri: "http://localhost:5172/api/bar",
    api_manageBar_uri: "http://localhost:5172/api/managebar"
};

export {
    Log,
    UserManager
};

```
### For the API
Create an `appsettings.json` file in the root of the API folder and fill in the `<blanks>`.

```
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
    }
  },
  "AllowedHosts": "*",
  "Jwt": {
    "Authority": "<your authority>",
    "Audience": "<your audience>"
  },
  "Cors": {
    "Origin": "http://localhost:3000"
  }
}
```

## Build and deploy the services
### Using Docker
```
docker-compose -f docker-compose.yml build
docker-compose -f docker-compose.yml up
```

## Test it
Browse to http://localhost:3000