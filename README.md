# loopback-ds-authorization-mixin

A mixin to automatically generate authorization for loopback Models

In the model, add the configuration, it can work. When we have time, we will complete the plugin at first time.

```javascript
var article.json = {
  "name": "article",
  ...
  "mixins": {
    "Authorization": {
      "dataSourcesName": "USRIC-DataBase",
      "userModelName": "user",
      "roleModelName": "role",
      "adminRoleName": "admin",
      "guestAccess": false
    }
  }
}
```
