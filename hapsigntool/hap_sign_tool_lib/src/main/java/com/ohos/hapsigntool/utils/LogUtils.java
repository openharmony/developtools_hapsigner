/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.utils;

import com.ohos.hapsigntool.error.LogConfigException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Hap Sign Tool LogUtils
 *
 * @since 2024/12/08
 */
public class LogUtils {
    private static Logger logger;
    private static Level level;
    private static final Map<String, Level> LEVEL_MAP = new HashMap<>();
    private static final String DEFAULT_LEVEL = "info";

    static {
        LEVEL_MAP.put(DEFAULT_LEVEL, Level.INFO);
        LEVEL_MAP.put("debug", Level.CONFIG);
        LEVEL_MAP.put("warn", Level.WARNING);
        LEVEL_MAP.put("error", Level.SEVERE);
        String configFileName = "log.config";

        try {
            level = LEVEL_MAP.get(getJarConfig(configFileName));
        } catch (LogConfigException e) {
            level = LEVEL_MAP.get(getResourceConfig(configFileName));
        }
    }

    private static String getJarConfig(String configFileName) throws LogConfigException {
        String parent = getString();
        if (parent == null) {
            throw new LogConfigException("read jar path failed");
        }
        File config = new File(parent, configFileName);
        if (!config.exists()) {
            throw new LogConfigException("read jar path failed");
        }
        try (FileInputStream fis = new FileInputStream(config)) {
            return getLevelByInStream(fis);
        } catch (IOException e) {
            throw new LogConfigException("read jar path failed");
        }
    }

    private static String getString() throws LogConfigException {
        ProtectionDomain protectionDomain = LogUtils.class.getProtectionDomain();
        if (protectionDomain == null) {
            throw new LogConfigException("read jar path failed");
        }
        CodeSource codeSource = protectionDomain.getCodeSource();
        if (codeSource == null) {
            throw new LogConfigException("read jar path failed");
        }
        URL location = codeSource.getLocation();
        if (location == null) {
            throw new LogConfigException("read jar path failed");
        }
        String jarPath = location.getFile();
        if (jarPath == null) {
            throw new LogConfigException("read jar path failed");
        }
        return new File(jarPath).getParent();
    }

    private static String getResourceConfig(String configFileName) {
        try (InputStream inputStream = LogUtils.class.getClassLoader().getResourceAsStream(configFileName)) {
            if (inputStream == null) {
                return DEFAULT_LEVEL;
            } else {
                return getLevelByInStream(inputStream);
            }
        } catch (IOException e) {
            return DEFAULT_LEVEL;
        }
    }

    private static String getLevelByInStream(InputStream is) throws IOException {
        Properties prop = new Properties();
        prop.load(is);
        Object levelConfig = prop.get("level");
        if (levelConfig instanceof String) {
            return (String) levelConfig;
        }
        return DEFAULT_LEVEL;
    }


    /**
     * format log utils constructor.
     *
     * @param clazz class
     */
    public LogUtils(Class<?> clazz) {
        logger = Logger.getLogger(clazz.getName());
        logger.setUseParentHandlers(false);
        ConsoleHandler consoleHandler = new ConsoleHandler();
        SignToolFormatter signToolFormatter = new SignToolFormatter();
        consoleHandler.setFormatter(signToolFormatter);
        logger.addHandler(consoleHandler);
        logger.setLevel(level);
    }

    /**
     * print info log
     *
     * @param log log string
     */
    public void info(String log) {
        logger.info(" INFO - " + log);
    }

    /**
     * print warn log
     *
     * @param log log string
     */
    public void warn(String log) {
        logger.warning(" WARN - " +  log);
    }

    /**
     * print warn log
     *
     * @param log log string
     * @param e throwable
     */
    public void warn(String log, Throwable e) {
        logger.log(Level.WARNING, e, () -> " DEBUG - " + log);
    }

    /**
     * print debug log
     *
     * @param log log string
     */
    public void debug(String log) {
        logger.config(" DEBUG - " +  log);
    }

    /**
     * print debug log
     *
     * @param log log string
     * @param e throwable
     */
    public void debug(String log, Throwable e) {
        logger.log(Level.CONFIG, e, () -> " DEBUG - " + log);
    }

    /**
     * print error log
     *
     * @param log log string
     */
    public void error(String log) {
        logger.severe(" ERROR - " +  log);
    }

    /**
     * print error log
     *
     * @param log log string
     * @param e throwable
     */
    public void error(String log, Throwable e) {
        logger.log(Level.SEVERE, e, () -> " ERROR - " + log);
    }
}
