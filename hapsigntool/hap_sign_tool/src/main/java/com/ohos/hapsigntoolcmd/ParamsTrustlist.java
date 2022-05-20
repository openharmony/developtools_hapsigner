package com.ohos.hapsigntoolcmd;

import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

/**
 * 入参白名单获取类
 */
public final class ParamsTrustlist {

    public static final String OPTIONS = " [options]:";

    private static  final List<String>  COMMONDS = new ArrayList<String>();

    private static HashMap<String, List<String>> trustMap = new HashMap<>();

    private ParamsTrustlist() {
    }

    static {
        COMMONDS.add(CmdUtil.Method.GENERATE_KEYPAIR + OPTIONS);
        COMMONDS.add(CmdUtil.Method.GENERATE_CSR + OPTIONS);
        COMMONDS.add(CmdUtil.Method.GENERATE_CERT + OPTIONS);
        COMMONDS.add(CmdUtil.Method.GENERATE_CA + OPTIONS);
        COMMONDS.add(CmdUtil.Method.GENERATE_APP_CERT + OPTIONS);
        COMMONDS.add(CmdUtil.Method.GENERATE_PROFILE_CERT + OPTIONS);
        COMMONDS.add(CmdUtil.Method.SIGN_PROFILE + OPTIONS);
        COMMONDS.add(CmdUtil.Method.VERIFY_PROFILE + OPTIONS);
        COMMONDS.add(CmdUtil.Method.SIGN_APP + OPTIONS);
        COMMONDS.add(CmdUtil.Method.VERIFY_APP + OPTIONS);
    }

    /**
     * Generate Trustlist
     */
    public  static void generateTrustlist() {
        ClassLoader classLoader = ParamsTrustlist.class.getClassLoader();
        if (classLoader == null) {
            return ;
        }
        String page = "help.txt";
        String str = "";
        try (InputStream inputStream = classLoader.getResourceAsStream(page)) {
            if (inputStream == null) {
                return ;
            }
            InputStreamReader isr = new InputStreamReader(inputStream);
            BufferedReader br = new BufferedReader(isr);
            String tempCommond = null;
            while ((str=br.readLine()) != null) {
                String param = str.trim();
                if (COMMONDS.contains(param)) {
                    tempCommond = param;
                    continue;
                }
                tempCommond = putTrustMap(tempCommond, param);
            }
        } catch (IOException ioe) {
            CustomException.throwException(ERROR.READ_FILE_ERROR, "Failed to read " + page + " resource");
        }

    }

    private static String putTrustMap(String tempCommond, String param) {
        if (tempCommond != null) {
            if (param.startsWith("-")) {
                String subParam = param.substring(0, param.indexOf(":")).trim();
                List<String> trustLists = Optional.ofNullable(
                        trustMap.get(tempCommond)).orElse(new ArrayList<>());
                trustLists.add(subParam);
                trustMap.put(tempCommond,trustLists);
            } else {
                tempCommond = null;
            }
        }
        return tempCommond;
    }

    /**
     *Get Trustlist
     *
     * @param commond commond
     * @return  TrustList
     */
    public static List<String> getTrustList(String commond) {
      generateTrustlist();
      String keyParam = commond + OPTIONS;
      if (trustMap.containsKey(keyParam)) {
          return trustMap.get(keyParam);
      }
      return null;
    }

}
