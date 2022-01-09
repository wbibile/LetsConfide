package org.letsconfide;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.letsconfide.config.ConfigParserTest;
import org.letsconfide.platform.tpm.AESWrapUnwrapHandlerTest;
import org.letsconfide.platform.tpm.TpmUtilsTest;

@RunWith(Suite.class)
@Suite.SuiteClasses({TestMain.class, ConfigParserTest.class, TpmUtilsTest.class, AESWrapUnwrapHandlerTest.class})
public class TestSuite {}
