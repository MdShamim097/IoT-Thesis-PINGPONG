package edu.uci.iotproject.filenaming;
public class Naming {
    public static String getName(String path,String eventName)
    {
        String []tokens = path.split("/");
        String ans = "";
        for(int i=0;i+1< tokens.length;i++)
        {
            ans = ans + tokens[i]+"/";
        }
        if(tokens.length>0) ans = ans + eventName + "-" + tokens[tokens.length-1];
        return ans;
    }
}