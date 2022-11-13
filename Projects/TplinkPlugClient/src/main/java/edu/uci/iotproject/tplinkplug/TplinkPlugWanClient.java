package edu.uci.iotproject.tplinkplug;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * TODO add class documentation.
 *
 * @author Janus Varmarken
 */
public class TplinkPlugWanClient {

//    private Client mRestClient = ClientBuilder.newClient();

    public TplinkPlugWanClient() {

    }

    public void powerOn() {
        System.out.println(String.format("%s.powerOn() invoked", getClass().getSimpleName()));
        sendRequest(PlugCommand.ON);
    }

    public void powerOff() {
        System.out.println(String.format("%s.powerOff() invoked", getClass().getSimpleName()));
        sendRequest(PlugCommand.OFF);
    }

    private void sendRequest(PlugCommand plugCommand) {

        String url = String.format("%s/?token=%s", Configuration.getAppServerUrl(), Configuration.getLoginToken());
        String payload = buildSetRelayStatePayload(plugCommand);

        try {
            HttpResponse<JsonNode> response = Unirest.post(url).
                    header("cache-control", "no-cache").
                    header("Content-Type", MediaType.APPLICATION_JSON).
                    body(payload).asJson();
            String debug = null;
        } catch (UnirestException e) {
            e.printStackTrace();
        }

//        Response response = mRestClient.target(url).request(MediaType.APPLICATION_JSON).
//                header("cache-control", "no-cache").
//                header("Content-Type", MediaType.APPLICATION_JSON).
//                post(Entity.text(payload));

        // TODO actually parse the response.
        String debugPoint = null;
    }

    private String buildSetRelayStatePayload(PlugCommand command) {
        return String.format("{ \"method\":\"passthrough\", \"params\": { \"deviceId\": \"%s\", \"requestData\": \"{\\\"system\\\":{\\\"set_relay_state\\\":{\\\"state\\\":%d}}}\"}}",
                Configuration.getDeviceId(), command.equals(PlugCommand.ON) ? 1 : 0);
    }

    private static enum PlugCommand {
        ON, OFF
    }
}