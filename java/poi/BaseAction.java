package com.cmos.mamp.action;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.servlet.ShiroHttpSession;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.struts2.ServletActionContext;

import com.ai.common.xml.bean.Output;
import com.ai.common.xml.util.ControlConstants;
import com.ai.frame.ICacheService;
import com.ai.frame.bean.InputObject;
import com.ai.frame.bean.OutputObject;
import com.ai.frame.logger.Logger;
import com.ai.frame.logger.LoggerFactory;
import com.ai.frame.util.JsonUtil;
import com.cmos.mamp.control.IControlService;
import com.cmos.mamp.exception.MampException;
import com.cmos.mamp.privilege.CaptchaUsernamePasswordToken;
import com.cmos.mamp.privilege.EncryptUtil;
import com.cmos.mamp.service.IUserService;
import com.cmos.mamp.utils.Constants;
import com.cmos.mamp.utils.Constants.RESTFUL_ACTION;
import com.cmos.mamp.utils.DateUtil;
import com.cmos.mamp.utils.DateUtil.DATE_PATTERN;
import com.cmos.mamp.utils.ExcelUtil;
import com.cmos.mamp.utils.HttpClientUtil;
import com.cmos.mamp.utils.PropertiesUtil;
import com.cmos.mamp.utils.StringUtil;
import com.jcraft.jsch.SftpException;
import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.util.ValueStack;

/**
 * Action基类
 */
public abstract class BaseAction extends ActionSupport {
    private static final long   serialVersionUID = 1581119741116374826L;
    private static final Logger logger           = LoggerFactory.getActionLog(BaseAction.class);
    private IControlService     controlService;                                                 // 前后工程调用服务
    private ICacheService       cacheService;                                                   // 缓存服务
    private InputObject         inputObject;
    private IUserService        userService;

    public IUserService getUserService() {
        return userService;
    }

    public void setUserService(IUserService userService) {
        this.userService = userService;
    }

    /** Get the request Object **/
    public HttpServletRequest getRequest() {
        return ServletActionContext.getRequest();
    }

    /** Get the response Object **/
    public HttpServletResponse getResponse() {
        return ServletActionContext.getResponse();
    }

    /** Get the current Session **/
    public HttpSession getSession() {
        return getRequest().getSession();
    }

    /** Get the current Session **/
    public HttpSession getSession(boolean arg0) {
        return getRequest().getSession(arg0);
    }

    /** Get the Servlet Context **/
    public ServletContext getServletContext() {
        return ServletActionContext.getServletContext();
    }

    /** Get the Value Stack of Struts2 **/
    public ValueStack getValueStack() {
        return ServletActionContext.getValueStack(getRequest());
    }

    /** Get the IControlService Object **/
    public IControlService getControlService() {
        return controlService;
    }

    public void setControlService(IControlService controlService) {
        this.controlService = controlService;
    }

    /** Get the ICacheService Object **/
    public ICacheService getCacheService() {
        return cacheService;
    }

    public void setCacheService(ICacheService cacheService) {
        this.cacheService = cacheService;
    }

    /** Print OutputStream to the Browser **/
    public void sendJson(String json) {
        try {
            getResponse().setContentType("text/html");
            getResponse().getWriter().print(json);
            logger.info("sendJson", json);
        } catch (IOException e) {
            logger.error("sendJson", "Exception Occured When Send Json to Client !", e);
        }
    }

    /** Get InputObject Object Encapsulated **/
    public InputObject getInputObject() {
        inputObject = (InputObject)ActionContext.getContext().get(ControlConstants.INPUTOBJECT);
        return inputObject;
    }

    /** Call Services and Get OutputObject Object **/
    public OutputObject getOutputObject() {
        return getOutputObject(getInputObject());
    }

    /** Call Services and Get OutputObject Object **/
    public OutputObject getOutputObject(InputObject inputObject) {
        OutputObject object = null;
        String cacheKey = inputObject.getParams().get(ControlConstants.CACHE_KEY);
        if (cacheKey == null) {// 不从缓存取
            object = this.execute(inputObject);
        } else {// 从缓存取
            try {
                String value = getCacheService().getFromCache(cacheKey);
                object = JsonUtil.json2OutputObject(value);
                if (object == null) {
                    object = this.execute(inputObject);
                    if (ControlConstants.RETURN_CODE.IS_OK.equals(object)) {// 调用成功
                        String seconds = inputObject.getParams().get(ControlConstants.SECONDS);
                        if (StringUtil.isNotEmpty(seconds) && StringUtil.isNum(seconds)
                                && Integer.parseInt(seconds) > 0) {
                            getCacheService().put2Cache(cacheKey, JsonUtil.convertObject2Json(object),
                                Integer.parseInt(seconds));
                        } else {
                            getCacheService().put2Cache(cacheKey, JsonUtil.convertObject2Json(object));
                        }
                    }
                }
            } catch (Exception e) {
                object = new OutputObject(ControlConstants.RETURN_CODE.SYSTEM_ERROR, e.getMessage());
            }

        }
        return object;
    }

    private OutputObject execute(InputObject inputObject) {
        OutputObject outputObject = null;
        try {
            outputObject = getControlService().execute(inputObject);
        } catch (Exception e) {
            logger.error("", "Invoke Service Error.", inputObject.getService() + "." + inputObject.getMethod(), e);
        }
        return outputObject;
    }

    /**
     * Json String Unified Conversion Method
     * @param outputObject
     * @return Json
     */
    public String convertOutputObject2Json(OutputObject outputObject) {
        return convertOutputObject2Json(getInputObject(), outputObject);
    }

    /**
     * Json String Unified Conversion Method
     * @param outputObject
     * @return Json
     */
    public String convertOutputObject2Json(InputObject inputObject, OutputObject outputObject) {
        String json = "";
        if (outputObject == null || inputObject == null) {
            return json;
        }

        Output output = (Output)ActionContext.getContext().get(ControlConstants.OUTPUT);
        try {
            // 如果配置了相应的IConvertor则执行，否则执行默认的Json转换功能
            if (output != null && StringUtil.isNotEmpty(output.getConvertor())) {
                json = JsonUtil.outputObject2Json(output.getConvertor(), output.getMethod(), inputObject, outputObject);
            } else {
                json = JsonUtil.outputObject2Json(outputObject);
            }
        } catch (Exception e) {
            logger.error("convertOutputObject", "Convert Output Error.", "", e);
        }
        return json;
    }

    protected void convertOutputError(OutputObject outputObject, Exception e) {
        outputObject.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
        outputObject.setReturnMessage(
            e.getMessage() == null ? e.getCause() == null ? "系统异常!" : e.getCause().getMessage() : e.getMessage());
        logger.error("", outputObject.getReturnMessage(), e);
    }

    protected void convertOutputError(OutputObject outputObject, String errMsg, Exception e) {
        outputObject.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
        String exceptionMsg = e.getMessage() == null ? e.getCause() == null ? "系统异常!" : e.getCause().getMessage()
            : e.getMessage();

        outputObject.setReturnMessage(StringUtil.isNotEmpty(errMsg) ? errMsg : exceptionMsg);
        logger.error("", outputObject.getReturnMessage(), e);
    }

    /**
     * 系统授权公用方法调用
     * 入参：目标url地址；
     * 对于第三方平台，入参还必须包含：渠道id、code
     */
    public void userOauth1() {
        InputObject inputObject = getInputObject();
        OutputObject outputObject = getOutputObject();
        Map<String, String> map = inputObject.getParams();
        String redirectUrl = map.get("redirectUrl"); // 目标url
        String chnlId = map.get("chnlId"); // 渠道
        if (!isTrueForChnl(chnlId)) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的渠道编号不合法！");
            sendJson(convertOutputObject2Json(outputObject));
            return;
        }
        String code = map.get("code"); // 第三方系统传过来的code
        String srcUserId = map.get("userId"); // 用户id
        logger.info("鉴权userOauth，调用入参：", JsonUtil.convertObject2Json(map));
        if (StringUtil.isEmpty(redirectUrl)) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的目标URL地址不能为空");
            sendJson(convertOutputObject2Json(outputObject));
            return;
        } else if (!redirectUrl.startsWith("http")) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的目标URL格式错误");
            sendJson(convertOutputObject2Json(outputObject));
            return;
        } else if (StringUtil.isEmpty(chnlId)) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的渠道地址不能为空");
            sendJson(convertOutputObject2Json(outputObject));
            return;
        } else {
            Subject subject = SecurityUtils.getSubject();
            Session session = subject.getSession();
            String sessionUserId = (String)session.getAttribute("userId");
            // 主动鉴权
            if (StringUtil.isEmpty(code)) {
                // 用户没有登录
                if (StringUtil.isEmpty(sessionUserId)) {
                    otherOauth(getResponse(), chnlId, redirectUrl);
                    return;
                    // 用户已经登陆，直接跳转
                } else {
                    ownOauth(getResponse(), redirectUrl);
                    return;
                }
                // 被动鉴权
            } else {
                // 将code回传给第三方平台
                InputObject inObj = new InputObject();
                inObj.getParams().put("code", code);
                logger.info("鉴权userOauth：入参code为：", code);
                inObj.getParams().put("chnlId", chnlId);
                // 通过htpclient请求
                // outputObject = getCodeRequest(inObj, outputObject);
                // 通过能力管控平台请求
                inObj.getParams().put("userId", srcUserId);
                outputObject = getCode(inObj);
                // code验证
                boolean isTrue = checkCode(outputObject);
                if (!isTrue) {
                    sendJson(convertOutputObject2Json(outputObject));
                    return;
                } else {
                    String accessToken = outputObject.getBean().get("accessToken");
                    if (StringUtil.isEmpty(accessToken)) {
                        ownOauth(getResponse(), redirectUrl);
                        return;
                    } else {
                        // 回传token进行token验证
                        inObj.getParams().clear();
                        inObj.getParams().put("accessToken", accessToken);
                        inObj.getParams().put("chnlId", chnlId);
                        // 通过httpclient请求
                        // outputObject = getTokenRequest(inObj, outputObject);
                        // 通过能力管控平台请求
                        inObj.getParams().put("userId", srcUserId);
                        outputObject = getToken(inObj);
                        // token验证
                        isTrue = checkToken(outputObject);
                        if (!isTrue) {
                            sendJson(convertOutputObject2Json(outputObject));
                            return;
                        } else {
                            String userNm = outputObject.getBean().get("userLoginId");
                            srcUserId = outputObject.getBean().get("userId");
                            // 根据userNm查询是否已经存在
                            String userId = "";
                            // 使用缓存
                            Map<String, String> useMap = userService.queryUserBySrcUserId(srcUserId, chnlId);
                            if (useMap != null && useMap.size() > 0) {
                                userId = useMap.get("userId");
                            }

                            // 如果用户为空，需要保存入数据库
                            if (StringUtil.isEmpty(userId)) {
                                userId = getSequence("T_PV_USR_ACCT");
                                // 保存用户信息，走mq
                                Map<String, String> userMap = new HashMap<String, String>();
                                userMap.put("newUserId", userId);
                                userMap.put("userNm", userNm);
                                userMap.put("srcChnlId", chnlId);
                                userMap.put("acctTypeCd", Constants.ACCT_TYPE_CD.ACCT_TYPE_CD_GENERAL);
                                Map<String, String> encryptMap = EncryptUtil.encrypt(userNm, Constants.SYS_INIT_PWD);
                                userMap.putAll(encryptMap);
                                userMap.put("srcUserId", srcUserId);
                                userService.saveUserAcct(userMap);
                            }

                            // 判断用户是否一样
                            if (userId.equals(sessionUserId) && StringUtil.isNotEmpty(sessionUserId)) {
                                // 已经登陆，直接跳转
                                ownOauth(getResponse(), redirectUrl);
                                return;
                            } else {
                                // 虚拟登陆
                                try {
                                    virtuaLogin(userId, chnlId, userNm, srcUserId);
                                } catch (Exception e) {
                                    logger.info("虚拟登陆失败，原因为：", outputObject.getReturnMessage(), e);
                                    outputObject.setReturnMessage("虚拟登陆失败，原因为：" + outputObject.getReturnMessage());
                                    sendJson(convertOutputObject2Json(outputObject));
                                    return;
                                }
                                // 登陆成功后，跳转至指定页面
                                ownOauth(getResponse(), redirectUrl);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * 系统授权公用方法调用
     * 入参：目标url地址；
     * 对于第三方平台，入参还必须包含：渠道id、code
     */
    public void userOauth() {
        InputObject inputObject = getInputObject();
        OutputObject outputObject = new OutputObject();
        outputObject.setReturnCode("0");
        Map<String, String> map = inputObject.getParams();
        String redirectUrl = map.get("redirectUrl"); // 目标url
        String chnlId = map.get("chnlId"); // 渠道
        String crossFlag = map.get("crossFlag"); // 支持跨域调用
        // 校验渠道
        if (!isTrueForChnl(chnlId)) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的渠道编号不合法！");
            sendJson(convertOutputObject2Json(outputObject));
            return;
        }
        String code = map.get("code"); // 第三方系统传过来的code
        String srcUserId = map.get("userId"); // 用户id
        logger.info("鉴权userOauth，调用入参：", JsonUtil.convertObject2Json(map));
        if (StringUtil.isEmpty(redirectUrl)) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的目标URL地址不能为空");
        } else if (!redirectUrl.startsWith("http")) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的目标URL格式错误");
        } else if (StringUtil.isEmpty(chnlId)) {
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage("传入的渠道地址不能为空");
        } else {
            // 校验传进来的url在发布管理中是否有对应关系
            redirectUrl = getRealUrl(redirectUrl);
            // 校验
            Subject subject = SecurityUtils.getSubject();
            Session session = subject.getSession();
            String sessionUserId = (String)session.getAttribute("userId");
            // 主动鉴权
            if (StringUtil.isEmpty(code)) {
                // 用户没有登录
                if (StringUtil.isEmpty(sessionUserId)) {
                    String loginUrl = getLoginUrl(chnlId);
                    String str;
                    if (loginUrl.contains("?")) {
                        str = "&";
                    } else {
                        str = "?";
                    }
                    try {
                        String url = loginUrl + str + "chnlId=" + chnlId + "&actUrl="
                                + URLEncoder.encode(redirectUrl, "UTF-8");
                        outputObject.getBean().put("url", url);
                    } catch (Exception e) {
                        logger.info("url编码异常", e.getMessage(), e);
                    }
                    // 用户已经登陆，直接跳转
                } else {
                    ownOauthV2(outputObject, redirectUrl);
                }
                // 被动鉴权
            } else {
                // 将code回传给第三方平台
                InputObject inObj = new InputObject();
                inObj.getParams().put("code", code);
                logger.info("鉴权userOauth：入参code为：", code);
                inObj.getParams().put("chnlId", chnlId);
                // 通过能力管控平台请求
                inObj.getParams().put("userId", srcUserId);
                outputObject = getCode(inObj);
                // code验证
                boolean isTrue = checkCode(outputObject);
                if (!isTrue) {
                    logger.info("根据code鉴权失败！", "出参为：" + JsonUtil.convertObject2Json(outputObject));
                    sendJson(convertOutputObject2Json(outputObject));
                    return;
                } else {
                    String accessToken = outputObject.getBean().get("accessToken");
                    if (StringUtil.isEmpty(accessToken)) {
                        ownOauthV2(outputObject, redirectUrl);
                    } else {
                        // 回传token进行token验证
                        inObj.getParams().clear();
                        inObj.getParams().put("accessToken", accessToken);
                        logger.info("鉴权userOauth：入参accessToken为：", accessToken);
                        inObj.getParams().put("chnlId", chnlId);
                        // 通过能力管控平台请求
                        inObj.getParams().put("userId", srcUserId);
                        outputObject = getToken(inObj);
                        // token验证
                        isTrue = checkToken(outputObject);
                        if (!isTrue) {
                            logger.info("根据token鉴权失败！", "出参为：" + JsonUtil.convertObject2Json(outputObject));
                            sendJson(convertOutputObject2Json(outputObject));
                            return;
                        } else {
                            // 登陆账号、用户第三方平台id、用户别名
                            String userNm = outputObject.getBean().get("userLoginId");
                            srcUserId = outputObject.getBean().get("userId");
                            String userAls = outputObject.getBean().get("userNm");
                            // 根据userNm查询是否已经存在
                            String userId = "";
                            // 使用缓存
                            Map<String, String> useMap = userService.queryUserBySrcUserId(srcUserId, chnlId);
                            if (useMap != null && useMap.size() > 0) {
                                userId = useMap.get("userId");
                            }

                            // 如果用户为空，需要保存入数据库
                            if (StringUtil.isEmpty(userId)) {
                                userId = getSequence("T_PV_USR_ACCT");
                                // 保存用户信息，走mq
                                Map<String, String> userMap = new HashMap<String, String>();
                                userMap.put("newUserId", userId);
                                userMap.put("userNm", userNm);
                                userMap.put("srcChnlId", chnlId);
                                userMap.put("userAls", userAls);
                                userMap.put("acctTypeCd", Constants.ACCT_TYPE_CD.ACCT_TYPE_CD_GENERAL);
                                Map<String, String> encryptMap = EncryptUtil.encrypt(userNm, Constants.SYS_INIT_PWD);
                                userMap.putAll(encryptMap);
                                userMap.put("srcUserId", srcUserId);
                                userService.saveUserAcct(userMap);
                            }

                            // 判断用户是否一样
                            if (userId.equals(sessionUserId) && StringUtil.isNotEmpty(sessionUserId)) {
                                // 已经登陆，直接跳转
                                ownOauthV2(outputObject, redirectUrl);
                            } else {
                                // 虚拟登陆
                                try {
                                    virtuaLogin(userId, chnlId, userNm, srcUserId);
                                } catch (Exception e) {
                                    logger.info("虚拟登陆失败，原因为：", e.getMessage(), e);
                                    outputObject.setReturnCode("-9999");
                                    outputObject.setReturnMessage("虚拟登陆失败，原因为：" + e.getMessage());
                                }
                                // 登陆成功后，跳转至指定页面
                                logger.info("用户" + userNm + "登陆成功：", JsonUtil.convertObject2Json(outputObject));
                                ownOauthV2(outputObject, redirectUrl);
                            }
                        }
                    }
                }
            }
            //将错误发送到前端使用
            String json;
            if ("true".equals(crossFlag)) { // 支持跨域
                json = "jsonCallback(" + convertOutputObject2Json(outputObject) + ")";
            } else {
                json = convertOutputObject2Json(outputObject);
            }
            sendJson(json);
        }
    }

    private String getRealUrl(String url) {
        InputObject inputObject = new InputObject();
        inputObject.setMethod("queryCmpgnUrlByOuturl");
        inputObject.setService("userService");
        inputObject.getParams().put("outsdLinkUrlAddr", url);
        OutputObject outputObject = getOutputObject(inputObject);
        Map<String, String> map = outputObject.getBean();
        String reUrl;
        if (map != null && !map.isEmpty()) {
            reUrl = map.get("cmpgnUrlAddr");
        } else {
            reUrl = url;
        }
        return reUrl;
    }


    /**
     * 获取code--通过httpclient获取
     * @param inputObject
     * @return
     */
    private OutputObject getCodeRequest(InputObject inputObject, OutputObject outputObject) throws MampException {
        Map<String, String> map = inputObject.getParams();
        String chnlId = map.get("chnlId");
        map.put("INTF_WHOLE_PATH", getCodeUrl(chnlId));// 服务地址
        map.put("CHAR_SET_CODE", "utf-8");// 字符集编码
        map.put("httpType", "http-get"); // http类型
        Map<String, String> reqMap = new HashMap<String, String>();
        reqMap.put("uid", "u001");
        reqMap.put("code", map.get("code"));
        try {
            String rep = doRequst(inputObject, reqMap);
            if (StringUtil.isNotEmpty(rep)) {
                outputObject = JsonUtil.json2OutputObject(rep);
            } else {
                outputObject.setReturnCode("-9999");
                outputObject.setReturnMessage("通过code调用第三方平台验证失败，返回结果为空");
                logger.error("通过code调用第三方平台验证失败：", "返回结果为空！");
            }
        } catch (Exception e) {
            logger.error("通过code调用第三方平台验证失败：", e.getLocalizedMessage(), e);
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage(e.getLocalizedMessage());
        }
        return outputObject;
    }

    /**
     * 获取code--通过能力管控平台
     * @param inputObject
     * @return
     */
    private OutputObject getCode(InputObject inputObject) {
        Map<String, String> map = inputObject.getParams();
        inputObject.setMethod("getCode");
        inputObject.setService("userService");
        map.put(RESTFUL_ACTION.SCOPE, RESTFUL_ACTION.ACT_GET);
        OutputObject outputObject = getOutputObject(inputObject);
        return outputObject;
    }

    /**
     * 验证code
     * @param inputObject
     * @return
     */
    private boolean checkCode(OutputObject outputObject) {
        boolean isTrue = false;
        if (outputObject.getReturnCode().equals(ControlConstants.RETURN_CODE.SYSTEM_ERROR)) {
            outputObject.setReturnMessage("根据code获取token接口调用失败，原因是：" + outputObject.getReturnMessage());
        } else {
            // 获取token
            Map<String, String> codeMap = outputObject.getBean();
            if ("02".equals(codeMap.get("success"))) {
                outputObject.setReturnMessage("code鉴权失败，原因为：" + outputObject.getReturnMessage());
            } else if ("01".equals(codeMap.get("success"))) {
                isTrue = true;
            } else {
                outputObject.setReturnCode("-9999");
                outputObject.setReturnMessage("code可能被篡改，鉴权失败！");
            }
        }
        return isTrue;
    }

    /**
     * 获取token--通过httpclient请求
     * @param inputObject
     * @return
     */
    private OutputObject getTokenRequest(InputObject inputObject, OutputObject outputObject) throws MampException {
        Map<String, String> map = inputObject.getParams();
        String chnlId = map.get("chnlId");
        map.put("INTF_WHOLE_PATH", getTokenUrl(chnlId));// 服务地址
        map.put("CHAR_SET_CODE", "utf-8");// 字符集编码
        map.put("httpType", "http-get"); // http类型
        Map<String, String> reqMap = new HashMap<String, String>();
        reqMap.put("uid", "u001");
        reqMap.put("accessToken", map.get("accessToken"));
        try {
            String rep = doRequst(inputObject, reqMap);
            outputObject = JsonUtil.json2OutputObject(rep);
        } catch (Exception e) {
            logger.error("通过accessToken调用第三方平台验证失败：", e.getMessage(), e);
            outputObject.setReturnCode("-9999");
            outputObject.setReturnMessage(e.getLocalizedMessage());
        }
        return outputObject;
    }

    /**
     * 获取第三方code服务地址
     */
    private String getCodeUrl(String chnlId) {
        String url = "";
        if (chnlId.equals(Constants.SYS_CHNL_ID.SYS_CHNL_ID_SH)) {
            url = PropertiesUtil.getString(Constants.SYSTEM_CODE_TOKEN_ADDR.APP_SH_ADDR_CODE);
        } else if (chnlId.equals(Constants.SYS_CHNL_ID.SYS_CHNL_ID_WSC)) {
            url = PropertiesUtil.getString(Constants.SYSTEM_CODE_TOKEN_ADDR.APP_WSC_ADDR_CODE);
        }
        return url;
    }

    /**
     * 获取第三方code服务地址
     */
    private String getTokenUrl(String chnlId) {
        String url = "";
        if (chnlId.equals(Constants.SYS_CHNL_ID.SYS_CHNL_ID_SH)) {
            url = PropertiesUtil.getString(Constants.SYSTEM_CODE_TOKEN_ADDR.APP_SH_ADDR_TOKEN);
        } else if (chnlId.equals(Constants.SYS_CHNL_ID.SYS_CHNL_ID_WSC)) {
            url = PropertiesUtil.getString(Constants.SYSTEM_CODE_TOKEN_ADDR.APP_WSC_ADDR_TOKEN);
        }
        return url;
    }

    /**
     * 验证token--通过能力管控平台
     * @param inputObject
     * @return
     */
    private OutputObject getToken(InputObject inputObject) {
        Map<String, String> map = inputObject.getParams();
        inputObject.setMethod("getToken");
        inputObject.setService("userService");
        map.put(RESTFUL_ACTION.SCOPE, RESTFUL_ACTION.ACT_GET);
        OutputObject outputObject = getOutputObject(inputObject);
        return outputObject;
    }

    /**
     * token验证
     * @param inputObject
     * @return
     */
    private boolean checkToken(OutputObject outputObject) {
        boolean isTrue = false;
        if (outputObject.getReturnCode().equals(ControlConstants.RETURN_CODE.SYSTEM_ERROR)) {
            outputObject.setReturnMessage("根据token查询用户信息接口调用失败，原因是：" + outputObject.getReturnMessage());
        } else {
            // 获取token
            Map<String, String> tokenMap = outputObject.getBean();
            if ("02".equals(tokenMap.get("success"))) {
                outputObject.setReturnMessage("token鉴权失败，原因为：" + outputObject.getReturnMessage());
            } else if ("01".equals(tokenMap.get("success"))) {
                isTrue = true;
            } else {
                outputObject.setReturnCode("-9999");
                outputObject.setReturnMessage("token可能被篡改，鉴权失败！");
            }
        }
        return isTrue;
    }

    /**
     * 虚拟登陆
     */
    public void virtuaLogin(String userId, String chnlId, String userNm, String srcUserId) throws MampException {
        Subject subject = SecurityUtils.getSubject();
        Session session = SecurityUtils.getSubject().getSession();
        try {
            String password = Constants.SYS_INIT_PWD;
            String ncode = "1234";
            session.setAttribute("ncode", ncode);
            String acctTypeCd = Constants.ACCT_TYPE_CD.ACCT_TYPE_CD_GENERAL;
            session.setAttribute("acctTypeCd", acctTypeCd);
            session.setAttribute("chnlId", chnlId);
            CaptchaUsernamePasswordToken token = new CaptchaUsernamePasswordToken(userNm, password, ncode);
            // 重新生成会话并登陆
            session = copeSession(subject, token);
            session.setAttribute("userNm", userNm);
            session.setAttribute("userId", userId);
            session.setAttribute("chnlId", chnlId);
            session.setAttribute("srcUserId", srcUserId);
            session.setAttribute("acctTypeCd", acctTypeCd);
        } catch (Exception e) {
            logger.error("虚拟登陆失败！", e.getMessage(), e);
            throw new MampException(e.getMessage());
        }

    }

    /**
     * 解决会话标识不更新问题，重新生成会话。
     * 复制原有session，生成新的session
     */
    public Session copeSession(Subject subject, CaptchaUsernamePasswordToken token) throws MampException {
        Session session = subject.getSession();
        final LinkedHashMap<Object, Object> attributes = new LinkedHashMap<Object, Object>();
        final Collection<Object> keys = session.getAttributeKeys();
        for (Object key : keys) {
            final Object value = session.getAttribute(key);
            if (value != null) {
                attributes.put(key, value);
            }
        }
        session.stop();
        subject.logout();
        // 创建新会话
        subject = SecurityUtils.getSubject();
        session = subject.getSession();
        for (final Object key : attributes.keySet()) {
            session.setAttribute(key, attributes.get(key));
        }
        // 登陆
        subject.login(token);
        // 修改COOKIE中JSESSIONID
        org.apache.shiro.web.servlet.Cookie cookie = new SimpleCookie(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        cookie.setValue((String)session.getId());
        cookie.setMaxAge(-1);
        cookie.setHttpOnly(true);
        cookie.saveTo(getRequest(), getResponse());
        return session;
    }

    /**
     * 登陆重定向，定向到第三方提供的登陆界面
     * @param request
     * @param response
     */
    private void otherOauth(HttpServletResponse response, String chnlId, String redirectUrl) {
        String loginUrl = getLoginUrl(chnlId);
        try {
            response
            .sendRedirect(loginUrl + "&chnlId=" + chnlId + "&actUrl=" + URLEncoder.encode(redirectUrl, "UTF-8"));
        } catch (Exception e) {
            logger.info("ERROR", "重定向到第三方登陆界面失败：", e);
        }
    }

    /**
     * 跳转到本系统指定页面
     * @param request
     * @param response
     */
    private static void ownOauth(HttpServletResponse response, String redirectUrl) {
        try {
            String newUrl=java.net.URLDecoder.decode(redirectUrl,"UTF-8");
            response.sendRedirect(newUrl);
        } catch (Exception e) {
            logger.info("ERROR", "跳转到系统指定界面失败：", e);
        }
    }

    /**
     * 跳转到本系统指定页面
     * @param request
     * @param response
     */
    public void ownOauthV2(OutputObject outputObject, String redirectUrl) {
        try {
            //url进行解码
            String newUrl;
            if (!redirectUrl.startsWith("http://")) {
                newUrl = java.net.URLDecoder.decode(redirectUrl, "UTF-8");
                if (!newUrl.startsWith("http://")) {
                    newUrl = java.net.URLDecoder.decode(newUrl, "UTF-8");
                }
            } else {
                newUrl = redirectUrl;
            }

            outputObject.getBean().put("url", newUrl);
        } catch (UnsupportedEncodingException e) {
            logger.info("目标url地址解码失败！", e.getMessage(),e);
        }
    }

    /**
     * 获取平台登录url地址
     * @param chnlId
     * @return
     */
    private String getLoginUrl(String chnlId) {
        // 获取登陆地址
        String loginUrl = null;
        InputObject inputObject = getInputObject();
        inputObject.setMethod("querySysConfigByChnlId");
        inputObject.setService("userService");
        inputObject.getParams().put("chnlId", chnlId);
        OutputObject outputObject = getOutputObject(inputObject);
        Map<String, String> map = outputObject.getBean();
        if (map != null && !map.isEmpty()) {
            loginUrl = map.get("chnlLoginAddr");
        }
        return loginUrl;
    }

    /**
     * 主键生成策略
     *
     * @param tableName
     *            需要获取主键的表名
     */
    private String getSequence(String tableName) {
        String redisKey = "REDIS_TBL_" + tableName;
        String id = null;
        try {
            logger.info("开始获取主键 ", "key=" + redisKey);
            id = DateUtil.date2String(new Date(), DATE_PATTERN.YYYYMMDDHHMMSSSSS) + ""
                    + getCacheService().incr(redisKey);
            logger.info("获取主键成功", "id=" + id);
        } catch (Exception e) {
            logger.error("使用redis获取主键失败，开始使用UUID", "key=" + redisKey, e);
            id = UUID.randomUUID().toString();
            logger.error("NOT ERROR! 主键获取成功", "key=" + redisKey + ",id=" + id);
        }
        return id;
    }

    /**
     * 发送请求
     * @param inputObject
     * @return
     * @throws MampException
     * @throws IOException
     */
    private String doRequst(InputObject inputObject, Map<String, String> reqMap) throws MampException, IOException {
        String rpsContent = null;
        if ("http-get".equals(inputObject.getParams().get("httpType"))) {
            // httpGet协议请求
            rpsContent = HttpClientUtil.getInstance().doHttpGet(inputObject, reqMap);
        } else if ("http-post".equals(inputObject.getParams().get("httpType"))) {
            // httpPost协议请求
            rpsContent = HttpClientUtil.getInstance().doHttpPost(inputObject, reqMap);
        }
        return rpsContent;
    }

    /**
     * 校验活动连接是否正常
     * @param inputObject
     * @return
     * @throws MampException
     * @throws IOException
     */
    public boolean checkCmpgnUrlValib() throws MampException {
        InputObject inputObject = getInputObject();
        Map<String, String> params = inputObject.getParams();
        Map<String, String> cloneMap = new HashMap<String, String>();
        cloneMap.putAll(params);
        String scope = inputObject.getParams().get("scope");
        String cmpgnId = inputObject.getParams().get("cmpgnId");
        // 校验当前活动id和活动连接是否吻合
        boolean isTrue = true;
        if (StringUtil.isNotEmpty(cmpgnId) && StringUtil.isNotEmpty(scope)) {
            String service = inputObject.getService();
            String method = inputObject.getMethod();
            inputObject.setMethod("getCmpgnInfo");
            inputObject.setService("userService");
            inputObject.getParams().put(RESTFUL_ACTION.SCOPE, RESTFUL_ACTION.ACT_GET);
            OutputObject outputObject = getOutputObject(inputObject);
            String returnCode = outputObject.getReturnCode();
            String returnMsg = outputObject.getReturnMessage();
            String opPath = inputObject.getLogParams().get("OP_PATH"); // 访问的url地址
            if (returnCode.equals(ControlConstants.RETURN_CODE.IS_OK)) {
                // 校验活动连接是否合法，需要根据营销活动返回的活动类型结果判断
                Map<String, String> map = outputObject.getBean();
                if (map != null && map.size() > 0) {
                    String cmpgnTypeCd = map.get("cmpgnTypeCd");
                    if (StringUtil.isNotEmpty(cmpgnTypeCd)) {
                        // 判断营销活动类型与请求地址是否对应
                        boolean checkTypeUrl = checkUrlByType(cmpgnTypeCd, opPath, cloneMap.get("uid"));
                        if (!checkTypeUrl) {
                            returnCode = ControlConstants.RETURN_CODE.SYSTEM_ERROR;
                            returnMsg = "非法的活动访问连接！";
                            isTrue = false;
                        }
                    } else {
                        returnCode = ControlConstants.RETURN_CODE.SYSTEM_ERROR;
                        returnMsg = "无效的营销活动！";
                        isTrue = false;
                    }
                }
                outputObject.setReturnCode(returnCode);
                outputObject.setReturnMessage(returnMsg);
            } else {
                isTrue = false;
            }
            inputObject.setService(service);
            inputObject.setMethod(method);
            inputObject.setParams(cloneMap);
        }
        return isTrue;
    }

    /**
     * 根据营销活动类型判断请求的action是否合法
     * @param type
     * @param urlAction
     * @return
     */
    private static boolean checkUrlByType(String type, String opPath, String uid) {
        boolean isTrue = false;
        String tmpType = "";
        // 特殊处理，无需登录即可访问，而且
        if (opPath.contains("front/sh/campaign!activity")) {
            switch (uid) {
            case "mk001":
            case "mk006":
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_TG;// 团购
                break;
            case "mk002":
            case "mk007":
            case "mk013":
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_MS; // 秒杀
                break;
            case "mk003":
            case "mk008":
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_CJ;// 抽奖
                break;
            case "mk004":
            case "mk009":
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_QD;// 签到
                break;
            case "mk005":
            case "mk010":
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_XC;// 宣传
                break;
            case "mk011":
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_HD;// 互动
                break;
            default:
                break;
            }
        } else {
            if (opPath.contains("front/sh/sign")) {
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_QD;
            } else if (opPath.contains("front/sh/seckill")) {
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_MS;
            } else if (opPath.contains("front/sh/groupbuy")) {
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_TG;
            } else if (opPath.contains("front/sh/luckdraw")) {
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_CJ;
            } else if (opPath.contains("front/sh/campaign")) {
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_XC;
            } else if (opPath.contains("front/sh/game")) {
                tmpType = Constants.CMPGN_TYPE_CD.CMPGN_TYPE_CD_HD;
            }
        }
        // 判断是否相等
        if (tmpType.equals(type)) {
            isTrue = true;
        }
        return isTrue;
    }

    // 判断渠道是否合法
    public static boolean isTrueForChnl(String chnlId) {
        boolean isTrue = false;
        if (Constants.sysChnlList.contains(chnlId)) {
            isTrue = true;
        }
        return isTrue;
    }

    /**
     * 使用新的分页参数重新调用,并把结果放到  outList 中
     * @author  穆凯
     * @date  2017年2月16日 下午5:32:37
     *
     *
     * @param paramMap
     * @param outList
     */
    private void invokeByNewPageToList(Map<String, String> paramMap, List<OutputObject> outList) {
        // 重新赋分页参数
        int pageCount = Integer.parseInt(paramMap.get("pageCount"));
        int pageSize = Integer.parseInt(paramMap.get("pageSize"));

        for (int i = 0; i < pageCount; i++) {
            // 循环调用，放入到list中，再分别写入到Excel.
            paramMap.put("start", String.valueOf(pageSize * i)); // 传入分页参数
            paramMap.put("limit", String.valueOf(pageSize));

            OutputObject out = this.getOutputObject();
            setExcelParam(paramMap, out.getBean()); // 必须有
            // 重新调用 end.
            logger.info("out getBeans ->", out.getBeans().toString());
            outList.add(out);
        }
    }

    /**
     * 设置Excel的参数 <br/>
     * excel_head_cnname 列头  <br/>
     * excel_data_enname 数据字段  <br/>
     * excel_data_cellSize 列宽  <br/>
     *
     * @param paramMap
     */
    private void setExcelParam(Map<String, String> srcMap, Map<String, String> descMap) {

        descMap.put(ExcelUtil.EXCEL_HEAD_NAME, srcMap.get(ExcelUtil.EXCEL_HEAD_NAME));
        descMap.put(ExcelUtil.EXCEL_DATA_NAME, srcMap.get(ExcelUtil.EXCEL_DATA_NAME));
        descMap.put(ExcelUtil.EXCEL_CELL_SIZE, srcMap.get(ExcelUtil.EXCEL_CELL_SIZE));
    }

    /**
     * 导出Excel，并传导sftp，完整下载路径放入outputObject的bean的url中
     * @author  穆凯
     * @date  2017年2月17日 下午5:09:03
     *
     *
     * @param inputObject
     * @param outputObject
     */
    public void exportExcelUrlToOut(InputObject inputObject, OutputObject outputObject) {
        Map<String, String> paramMap = inputObject.getParams();

        setExcelParam(paramMap, outputObject.getBean());

        try {
            // 重新设置分页参数，为重新调用做准备
            ExcelUtil.resetInputPage(inputObject, outputObject);

            List<OutputObject> outList = new ArrayList<>();

            if (ExcelUtil.TRUESTR.equals(paramMap.get(ExcelUtil.ISNOINVOKE))) {
                outList.add(outputObject);
            } else {
                // 重新调用，不需要原来的数据
                outputObject.setBeans(null);
                invokeByNewPageToList(paramMap, outList);
            }

            ExcelUtil.exportExcel(inputObject, outputObject, outList);
        } catch (MampException | SftpException | IOException e) {
            outputObject.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            outputObject.setReturnMessage("导出Excel失败:" + e.getMessage());
            logger.error("导出Excel失败", e.getMessage(), e);
        }
        outputObject.setBeans(null);
    }

    /**
     * 校验活动是否可用
     */
    public boolean checkCmpgnForAll() {
        boolean isTrue = false;
        InputObject inputObject = getInputObject();
        //克隆一个新的方法
        InputObject inObj = inputObject.copy("userService","checkCmpgnInfo");
        OutputObject outputObject = getOutputObject(inObj);
        String isValid = outputObject.getBean().get("isValid");
        if("true".equals(isValid)){
            isTrue = true;
        }
        return isTrue;
    }
    /**
     * 校验资源活动时间
     */
    public boolean checkRsTime() {
        boolean isTrue = false;
        InputObject inputObject = getInputObject();
        //克隆一个新的方法
        InputObject inObj = inputObject.copy("groupBuyService","checkRsTime");
        OutputObject outputObject = getOutputObject(inObj);
        String isValid = outputObject.getBean().get("isValid");
        if("true".equals(isValid)){
            isTrue = true;
        }
        return isTrue;
    }
}
