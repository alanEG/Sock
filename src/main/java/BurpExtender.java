package burp;
import java.awt.Component;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab,IProxyListener
{
    public PrintWriter stdout,stderr;
    private IExtensionHelpers helpers;
    public burp.IBurpExtenderCallbacks _callbacks;
    public static String extensionName = "Sock";
    public static extenderGui extenderGui;
    
    JsonObject jsonConfig;
    List<String> urlsHash = new ArrayList<>();
    
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        
        _callbacks = callbacks;
        // set our extension name
        _callbacks.setExtensionName(extensionName);
        
        extenderGui = new extenderGui();
        _callbacks.addSuiteTab(this);
        
        // register ourselves as an HTTP listener
        stdout = new PrintWriter(_callbacks.getStdout(), false);
        stderr = new PrintWriter(_callbacks.getStderr(), true);

        // register ourselves as an HTTP listener
        _callbacks.registerProxyListener(this);
        // register ourselves as a Scanner listener
        
        helpers = _callbacks.getHelpers();
    }
    
    @Override
    public String getTabCaption() {
        return extensionName;
    }
    @Override
    public Component getUiComponent() {
        return extenderGui;
    }
    
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
        URL url = helpers.analyzeRequest(message.getMessageInfo()).getUrl();
        if (!messageIsRequest && "Stop".equals(extenderGui.optionStatus) && loadJson() && !checkDublicate(url.toString()) && checkScope(url)){
            String proxyRespons = getResponse(message.getMessageInfo().getResponse());

            HashMap<String,List<String>> match = getMathRegex(jsonConfig,proxyRespons);
            if (!match.isEmpty()){
                for(Map.Entry<String, List<String>> entry : match.entrySet()) {
                    JsonObject messageObj = jsonConfig.get(entry.getKey()).getAsJsonObject();
                    List<String> entryValue = entry.getValue();
                    for (int i=0; i < entryValue.size();i++){
                        String socialUrl = entryValue.get(i); 
                        if (extenderGui.getOptionActiveCheck()  && !checkDublicate(socialUrl) ){
                            ActiveCheck(socialUrl,messageObj,url.toString());
                        } else if (!checkDublicate(socialUrl)) {
                            extenderGui.addToTable("Check_Disabled",socialUrl, url.toString());
                        }
                    }

                }
            }
        }
    }

    public boolean checkScope(URL url){
        String scopeList = _callbacks.saveConfigAsJson("target.scope.include"); 
        JsonParser parser = new JsonParser();
        JsonObject scopeJson = parser.parse(scopeList).getAsJsonObject();   
        JsonArray Json = ((JsonObject) ((JsonObject) scopeJson.get("target")).get("scope")).get("include").getAsJsonArray();
        if (Json.size() > 0){
            return _callbacks.isInScope(url);
        }
        return true;
    };

    //check if we did check url before
    public boolean checkDublicate(String url) {
        String hash = MD5(url);
        if (urlsHash.contains(hash)){
            return true;
        }
        
        urlsHash.add(hash);
        return false;
    }
    
    public String MD5(String md5) {
        try {
             java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
             byte[] array = md.digest(md5.getBytes());
             StringBuffer sb = new StringBuffer();
             for (int i = 0; i < array.length; ++i) {
               sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1,3));
            }
             return sb.toString();
         } catch (java.security.NoSuchAlgorithmException e) {
         }
         return null;
    }
    
    public byte[] sendRequest(String url){
        URL urlHand;
        try {
            urlHand = new URL(url);
            String urlPath = urlHand.getPath() != "" ? urlHand.getPath() : "/"; 
            Boolean isSSL = (urlHand.getProtocol().equals("https"));
            byte[] response = _callbacks.makeHttpRequest(urlHand.getHost(),urlHand.getPort() == -1 ? 443 : urlHand.getPort(),isSSL,
                ("GET " + urlPath + " HTTP/1.1\r\n"
                        + "Host: " + urlHand.getHost() + "\r\n"
                        + "Connection: close\r\n"
                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36\r\n"
                        + "Sec-Fetch-Site: same-origin\r\n" 
                        + "Accept: */*\r\n"
                        + "Accept-Language: en-US,en;q=0.9\r\n"
                        + "\r\n").getBytes(Charset.forName("UTF-8")));
            return response;
        } catch (MalformedURLException ex) {
            return ("Error_fetch").getBytes();
        }

    }
    
    public String getResponse(byte[] response){
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        String x =  new String(response).substring(responseInfo.getBodyOffset());
        return x;
    }
    
    
    public HashMap<String,List<String>> getMathRegex(JsonObject jsonObject,String response){
        
        Set<Map.Entry<String, JsonElement>> entries = jsonObject.entrySet();
        HashMap<String,List<String>> result = new HashMap<String, List<String>>(); 
        
        for (Map.Entry<String, JsonElement> entry: entries) {
            
            JsonObject elem = jsonObject.get(entry.getKey()).getAsJsonObject();
            Matcher m = Pattern.compile("(" + elem.get("urlRegex").getAsString() + ")",Pattern.MULTILINE).matcher(response);
            Pattern exclude = Pattern.compile("");
            if (elem.has("exclude")){
                exclude = Pattern.compile("(" + elem.get("exclude").getAsString() + ")");
            }

            if (m.groupCount() > 0){
                ArrayList<String> value = new ArrayList<String>();
                while (m.find()){
                    String valueGroup = m.group(0).replace("http:","https:");
                    if  (!value.contains(valueGroup) & !exclude.matcher(valueGroup).matches()){
                        value.add(valueGroup);
                    }
                
                }
                
                if (!value.isEmpty()){ 

                    result.put(entry.getKey(), value);

                }
            }
        }
        return result;
    }
    
    public void ActiveCheck(String url,JsonObject messageObj,String fromUrl){
        String type = messageObj.get("errorType").getAsString();
        Matcher m;
        IResponseInfo responseAnaluz; 
        byte[] response = sendRequest(url); 
        switch (type){
            case "message":
                m = Pattern.compile("(" + messageObj.get("errorMsg").getAsString() + ")").matcher(getResponse(response));
                if (m.find()){
                    extenderGui.addToTable("Vulnrable",url, fromUrl);
                } else {
                    extenderGui.addToTable("Not_Vulnrable",url, fromUrl); 
                }
                break;
            case "notMessage":
                m = Pattern.compile("(" + messageObj.get("errorMsg").getAsString() + ")").matcher(getResponse(response));
                if (!m.find()){
                    extenderGui.addToTable("Vulnrable",url, fromUrl);
                } else {
                    extenderGui.addToTable("Not_Vulnrable",url, fromUrl);
                }
                break;
            case "status_code":
                responseAnaluz = helpers.analyzeResponse(response);
                if (responseAnaluz.getStatusCode() == (int)messageObj.get("status_code").getAsInt()){
                    extenderGui.addToTable("Vulnrable",url, fromUrl);
                } else {
                    extenderGui.addToTable("Not_Vulnrable",url, fromUrl);
                }
                break;
            case "None":
                extenderGui.addToTable("Check_Disabled",url, fromUrl);
                break;
        }
    }
    
    public boolean loadJson(){
        
        if (extenderGui.jsonIsload){
            return extenderGui.jsonIsload;
        }
        
        String location = extenderGui.getRegexLocation();
        if (location.startsWith("http://") || location.startsWith("https://")){
            byte[] response = sendRequest(location); 
            for (int i=0;i < 5;i++){
                if (response.toString() != "Error_fetch"){
                    
                    String regex = getResponse(response);
                    JsonParser parser = new JsonParser();
                    jsonConfig = parser.parse(regex).getAsJsonObject();        
                    
                    if (jsonConfig.isJsonObject()){
                        extenderGui.jsonIsload = true;
                        stdout.println("load json done");
                        return true;
                    }
                    
                    extenderGui.jsonIsload = false;
                    stderr.println("Faild to load json");
                    return false;

                } else {
                    extenderGui.jsonIsload = false;
                    stderr.println("Can't fetch json url\nTry to fetch: " + i);
                    return false;
                }
            }
        } else {
            // handling as file 
        }
        return false;
    }
}
