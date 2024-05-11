/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ohos.hapsigntool.codesigning.utils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import com.ohos.hapsigntool.entity.Pair;
import com.ohos.hapsigntool.error.ProfileException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * utility for check hap configs
 *
 * @since 2023/06/05
 */
public class HapUtils {
    /**
     * DEBUG_LIB_ID
     */
    public static final String HAP_DEBUG_OWNER_ID = "DEBUG_LIB_ID";

    /**
     * SHARED_LIB_ID
     */
    public static final String HAP_SHARED_OWNER_ID = "SHARED_LIB_ID";

    private static final Logger LOGGER = LogManager.getLogger(HapUtils.class);

    private static final String COMPRESS_NATIVE_LIBS_OPTION = "compressNativeLibs";

    private static final List<String> HAP_CONFIG_FILES = new ArrayList<>();

    private static final String HAP_FA_CONFIG_JSON_FILE = "config.json";

    private static final String HAP_STAGE_MODULE_JSON_FILE = "module.json";

    private static final int MAX_APP_ID_LEN = 32; // max app-identifier in profile

    static {
        HAP_CONFIG_FILES.add(HAP_FA_CONFIG_JSON_FILE);
        HAP_CONFIG_FILES.add(HAP_STAGE_MODULE_JSON_FILE);
    }

    private HapUtils() {
    }

    /**
     * Check configuration in hap to find out whether the native libs are compressed
     *
     * @param hapFile the given hap
     * @return boolean value of parsing result
     * @throws IOException io error
     */
    public static boolean checkCompressNativeLibs(File hapFile) throws IOException {
        try (JarFile inputJar = new JarFile(hapFile, false)) {
            for (String configFile : HAP_CONFIG_FILES) {
                JarEntry entry = inputJar.getJarEntry(configFile);
                if (entry == null) {
                    continue;
                }
                try (InputStream data = inputJar.getInputStream(entry)) {
                    String jsonString = new String(InputStreamUtils.toByteArray(data, (int) entry.getSize()),
                        StandardCharsets.UTF_8);
                    return checkCompressNativeLibs(jsonString);
                }
            }
        }
        return true;
    }

    /**
     * Check whether the native libs are compressed by parsing config json
     *
     * @param jsonString the config json string
     * @return boolean value of parsing result
     */
    public static boolean checkCompressNativeLibs(String jsonString) {
        JsonObject jsonObject = JsonParser.parseString(jsonString).getAsJsonObject();
        Queue<JsonObject> queue = new LinkedList<>();
        queue.offer(jsonObject);
        while (queue.size() > 0) {
            JsonObject curJsonObject = queue.poll();
            JsonElement jsonElement = curJsonObject.get(COMPRESS_NATIVE_LIBS_OPTION);
            if (jsonElement != null) {
                return jsonElement.getAsBoolean();
            }
            for (Map.Entry<String, JsonElement> entry : curJsonObject.entrySet()) {
                if (entry.getValue().isJsonObject()) {
                    queue.offer(entry.getValue().getAsJsonObject());
                }
            }
        }
        // default to compress native libs
        return true;
    }

    /**
     * get app-id from profile
     *
     * @param profileContent the content of profile
     * @return string value of app-id
     * @throws ProfileException profile is invalid
     */
    public static String getAppIdentifier(String profileContent) throws ProfileException {
        Pair<String, String> resultPair = parseAppIdentifier(profileContent);
        String ownerID = resultPair.getFirst();
        String profileType = resultPair.getSecond();
        if ("debug".equals(profileType)) {
            return HAP_DEBUG_OWNER_ID;
        } else if ("release".equals(profileType)) {
            return ownerID;
        } else {
            throw new ProfileException("unsupported profile type");
        }
    }

    /**
     * parse app-id and profileType from profile
     *
     * @param profileContent the content of profile
     * @return Pair value of app-id and profileType
     * @throws ProfileException profile is invalid
     */
    public static Pair<String, String> parseAppIdentifier(String profileContent) throws ProfileException {
        String ownerID = null;
        String profileType = null;
        try {
            JsonElement parser = JsonParser.parseString(profileContent);
            JsonObject profileJson = parser.getAsJsonObject();
            String profileTypeKey = "type";
            if (!profileJson.has(profileTypeKey)) {
                throw new ProfileException("profile has no type key");
            }

            profileType = profileJson.get(profileTypeKey).getAsString();
            if (profileType == null || profileType.length() == 0) {
                throw new ProfileException("Get profile type error");
            }

            String appIdentifier = "app-identifier";
            String buildInfoMember = "bundle-info";
            JsonObject buildInfoObject = profileJson.getAsJsonObject(buildInfoMember);
            if (buildInfoObject == null) {
                throw new ProfileException("can not find bundle-info");
            }
            if (buildInfoObject.has(appIdentifier)) {
                JsonElement ownerIDElement = buildInfoObject.get(appIdentifier);
                if (!ownerIDElement.getAsJsonPrimitive().isString()) {
                    throw new ProfileException("value of app-identifier is not string");
                }
                ownerID = ownerIDElement.getAsString();
                if (ownerID.isEmpty() || ownerID.length() > MAX_APP_ID_LEN) {
                    throw new ProfileException("app-id length in profile is invalid");
                }

            }
        } catch (JsonSyntaxException | UnsupportedOperationException e) {
            LOGGER.error(e.getMessage());
            throw new ProfileException("profile json is invalid");
        }
        return Pair.create(ownerID, profileType);
    }

    /**
     *
     * @param profileContent
     * @return
     */
    public static String getHnpOwnerId(String profileContent) {
        //property type
        String publicOwnerID = "";
        JsonElement parser = JsonParser.parseString(profileContent);
        JsonObject profileJson = parser.getAsJsonObject();
        String profileTypeKey = "type";
        JsonPrimitive profileType = profileJson.getAsJsonPrimitive(profileTypeKey);
        if (profileType != null) {
            if ("debug".equals(profileType.getAsString())) {
                publicOwnerID = HAP_DEBUG_OWNER_ID;
            } else if ("release".equals(profileType.getAsString())) {
                publicOwnerID = HAP_SHARED_OWNER_ID;
            }
        }
        return publicOwnerID;
    }

    /**
     * get map of hnp name and type from module.json
     *
     * @param inputJar hap file
     * @return packageName-type map
     * @throws IOException
     */
    public static Map<String, String>  getHnpsFromJson(JarFile inputJar) throws IOException {
        //module.json
        Map<String, String> hnpNameMap = new HashMap<>();
        JarEntry moduleEntry = inputJar.getJarEntry("module.json");
        if (moduleEntry == null) {
            return hnpNameMap;
        }
        try (JsonReader reader = new JsonReader(
            new InputStreamReader(inputJar.getInputStream(moduleEntry), StandardCharsets.UTF_8))) {

            JsonElement jsonElement = JsonParser.parseReader(reader);
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonObject moduleObject = jsonObject.getAsJsonObject("module");
            JsonArray hnpPackageArr = moduleObject.getAsJsonArray("hnp_packages");
            if (hnpPackageArr == null || hnpPackageArr.isEmpty()) {
                LOGGER.info("profile has no hnp_package key or hnp_packages value is empty");
                return hnpNameMap;
            }
            hnpPackageArr.iterator().forEachRemaining((element) -> {
                JsonObject hnpPackage = element.getAsJsonObject();
                JsonPrimitive hnpName = hnpPackage.getAsJsonPrimitive("package");
                if (hnpName == null || hnpName.getAsString().isEmpty()) {
                    return;
                }
                hnpNameMap.put(hnpName.getAsString(), "private");
                JsonPrimitive type = hnpPackage.getAsJsonPrimitive("type");
                if (type != null && !type.getAsString().isEmpty()) {
                    hnpNameMap.put(hnpName.getAsString(), type.getAsString());
                }
            });
        }
        return hnpNameMap;
    }

}
