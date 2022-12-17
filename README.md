
# Sock

A burp extension can exteract the social url by the regex you pass and 
check if the finding is allow to hijacking or not 

# Installation

## build 
You can build the project by theses commands then import the jar file in 'build/lib/sock.jar' in burp   
```
git cloen https://github.com/alanEG/Sock
gradle build
```
## Install release 
Or donwload the latest release jar version then import to burp 

## Documentation
## Note 
`active check` option is require to enable check 
If you disable it the extension will add the account to result without checking 

This extension check on finding by regex pattern provided in the json file 

The default file is https://raw.githubusercontent.com/alanEG/Sock/main/resource/regex.json

Once you run the extension and receive the response it will load the json from default url or url you provided.

There are several json options available

### None 
Here is example for the option that get only the finding
```json
{
    "facebook": {
        "errorType": "None",
        "urlRegex": "https?://(www\\.)?facebook\\.com/[a-zA-Z0-9]"
    }
}
```
Nothing more here the extension will gets the links from response and load it to the table 

### message
If you need to check on finding
You can use the following json object

```json
{
  "facebook":{
    "errorType": "message",
    "errorMsg":"Facebook account/page not found",
    "urlRegex": "https?://(www\\.)?facebook\\.com/[a-zA-Z0-9]"
  }
}
```

This option tells to the extension to gets the `urlRegex` from response 
Then send request to the url then check if `errorMsg` in the response 
If it's. the extension will flag the finding url as `Vulnrable`

### notMessage
There is another option called `notMessage`
Example
```json
{
  "facebook":{
    "errorType": "notMessage",
    "errorMsg":"Account found",
    "urlRegex": "https?://(www\\.)?facebook\\.com/[a-zA-Z0-9]"
  }
}
```
By this option you tell to the extension if finding url response has this value in `errorMsg` that mean this account is `Not_Vulnrable`

### status_code
Also there is `status_code` option 
This match the status code of the finding request status
```json
{
  "facebook":{
    "errorType": "status_code",
    "status_code":404,
    "urlRegex": "https?://(www\\.)?facebook\\.com/[a-zA-Z0-9]"
  }
}
```

### exclude
This option exclude the finding by regex 
For example. the extension will add these urls to result 
```
https://facebook.com/help
https://facebook.com/setting
```
thses endpoints aren't accounts on facebook they's just endpoints and we don't need these endpoints 
So we have `exclude` option. It's exclude the finding by regex

Example
```json
{
  "facebook":{
    "errorType": "status_code",
    "status_code":404,
    "exclude":"https?://(www\\.)?facebook\\.com/(help|setting|etc..)"
    "urlRegex": "https?://(www\\.)?facebook\\.com/[a-zA-Z0-9]"
  }
}
```
