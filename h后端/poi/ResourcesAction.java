package com.cmos.mamp.action;

import java.io.IOException;
import java.io.InputStream;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellValue;
import org.apache.poi.ss.usermodel.DateUtil;
import org.apache.poi.ss.usermodel.FormulaEvaluator;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;

import com.ai.common.xml.util.ControlConstants;
import com.ai.frame.bean.InputObject;
import com.ai.frame.bean.OutputObject;
import com.ai.frame.logger.Logger;
import com.ai.frame.logger.LoggerFactory;
import com.ai.frame.util.ConvertUtil;
import com.ai.frame.util.JsonUtil;
import com.cmos.mamp.exception.MampException;
import com.cmos.mamp.utils.Constants;
import com.cmos.mamp.utils.ExcelUtil;
import com.cmos.mamp.utils.FtpUtil;
import com.cmos.mamp.utils.PropertiesUtil;
import com.cmos.mamp.utils.StringUtil;

/**
 * 通用类
 */
public class ResourcesAction extends BaseAction {
    private static final long   serialVersionUID   = 2021751417577646314L;
    private static final Logger LOGGER             = LoggerFactory.getActionLog(ResourcesAction.class);
    private static final String MCDSID             = "mcdsId";
    private static final String CHNLID             = "chnlId";
    private static final String REMOTESERVICE      = "remoteService";
    private static final String RSSERVICE          = "rsService";
    private static final String MCDSEXTDMDMTXT     = "mcdsExtdMdmtxt";
    private static final String REMOTEMETHOD       = "remoteMethod";
    private static final String RESOURCESSERVICE   = "resourcesService";
    private static final String INVOKEREMOTEMETHOD = "invokeRemoteMethod";
    private static final String RETURNMSG          = "returnMsg";
    private static final String SEPARATOR          = "";

    /** Uniform Method Invocation **/
    @Override
    public String execute() {
        LOGGER.info("execute", "Start");
        OutputObject object = super.getOutputObject();
        super.sendJson(super.convertOutputObject2Json(object));
        LOGGER.info("execute", "End");
        return null;
    }

    public String state() {
        OutputObject object = super.getOutputObject();
        super.sendJson(super.convertOutputObject2Json(object));
        return null;
    }

    /**
     * 此方法更改为本地方法，内部嵌套远程调用（busi层），再插入数据库
     * @author  穆凯
     * @date  2017年1月18日 下午6:06:16
     *
     *
     * @return
     */
    public String saveRemoteState() {
        OutputObject outputObject = super.getOutputObject();
        super.sendJson(super.convertOutputObject2Json(outputObject));
        return null;
    }

    public void index() {
        InputObject inputObject = super.getInputObject();
        String uid = inputObject.getParams().get("uid");
        if ("r001".equals(uid)) {
            Session session = SecurityUtils.getSubject().getSession();
            String chnlId = session.getAttribute(CHNLID).toString();
            // inputObject.setMethod(inputObject.getMethod() + getExtType(chnlId)); // 此层网络不通，先下放到busi层调用

            Map<String, String> inMap = inputObject.getParams();
            inMap.put(REMOTESERVICE, RSSERVICE);
            inMap.put(REMOTEMETHOD, inputObject.getMethod() + getExtType(chnlId));
            inMap.put(CHNLID, chnlId);
            inputObject.setService(RESOURCESSERVICE);
            inputObject.setMethod(INVOKEREMOTEMETHOD);

        }

        OutputObject object = super.getOutputObject(inputObject);
        String visitUrl = getInputObject().getLogParams().get("VISIT_URL");
        LOGGER.info("visitUrl", visitUrl);
        String readPath = PropertiesUtil.getString(Constants.SFTP_CONFIG.FTP_PREFIX_IN);
        object.getBean().put("prePath", readPath);

        super.sendJson(super.convertOutputObject2Json(object));
    }

    // 增加资源
    public void add() throws MampException {
        InputObject inputObject = super.getInputObject();
        OutputObject object = new OutputObject();

        String rsTypeCd = inputObject.getParams().get("rsTypeCd");
        String isMcds = inputObject.getParams().get("isMcds");
        // 优惠券需要导入
        if (Constants.RS_TYPE_CD.RS_TYPE_CD_YHJ.equals(rsTypeCd)) {
            String skuNo = removeSkuNoFromCache();
            if ("".equals(skuNo)) {
                object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
                object.setReturnMessage("优惠券编号不能为空");
            }
            inputObject.addParams("skuNo", "skuNo", skuNo);
        } else if (Constants.RS_TYPE_CD.RS_TYPE_CD_SW.equals(rsTypeCd) && "1".equals(isMcds)) {
            addMcds(inputObject, object); // 商品，包括规格、详情
        }
        if (!"-1".equals(object.getReturnCode())
                && !ControlConstants.RETURN_CODE.SYSTEM_ERROR.equals(object.getReturnCode())) {
            object = super.getOutputObject();
        }
        super.sendJson(super.convertOutputObject2Json(object));
    }

    public void updateSku() {
        OutputObject object = super.getOutputObject();
        super.sendJson(super.convertOutputObject2Json(object));
    }

    private String removeSkuNoFromCache() {
        String skuNo = "";
        Session session = SecurityUtils.getSubject().getSession();
        String userId = session.getAttribute("userId").toString();
        String excelChKey = "excel" + userId;
        try {
            skuNo = getCacheService().getFromCache(excelChKey);
            getCacheService().del(excelChKey);
        } catch (Exception e) {

            LOGGER.warn("获取和移除" + excelChKey + "缓存异常", e.getMessage());

            LOGGER.warn("MampException", e.getMessage(), e);

        }

        return skuNo;
    }

    /* 处理优惠券 */
    public void addSkuNo() {
        OutputObject object = new OutputObject();
        object.setReturnCode(ControlConstants.RETURN_CODE.IS_OK);
        List<String> skuList = new ArrayList<>();
        try {
            String fileContent = super.getInputObject().getParams().get("filecontent");
            if (StringUtil.isEmpty(fileContent)) {
                throw new MampException("excel不能为空");
            }

            skuList = exportListFromExcel(fileContent);
            int listSize = skuList.size();
            if (listSize == 0) {
                throw new MampException("没有解析到数据");
            }
            Set<String> set = new HashSet<>(skuList);
            int n = listSize - set.size();
            if (n != 0) {
                throw new MampException("导入失败：有" + n + "条重复数据");
            }

            String skuNo = JsonUtil.convertObject2Json(skuList);
            Session session = SecurityUtils.getSubject().getSession();
            String userId = session.getAttribute("userId").toString();
            String excelChKey = "excel" + userId;
            put2excelCache(excelChKey, skuNo);
            object.getBean().put("preprQty", String.valueOf(listSize));
        } catch (MampException | IOException e) {
            String errmsg = e.getMessage();
            object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.setReturnMessage(errmsg);
            if (errmsg == null) {
                errmsg = "请确定有无空数据";
            }
            object.getBean().put(RETURNMSG, "解析失败：" + errmsg);
            LOGGER.warn("MampException", e.toString());

            LOGGER.warn("解析excel失败：", errmsg, e);
        }

        super.sendJson(super.convertOutputObject2Json(object));
    }

    private void put2excelCache(String excelChKey, String skuNo) throws MampException {
        try {
            getCacheService().put2Cache(excelChKey, skuNo, 24 * 60 * 60);// 一天
        } catch (Exception e) {
            throw new MampException(e);
        }
    }

    /* 处理商品，在资源中进行处理 */
    private void addMcds(InputObject inputObject, OutputObject object) throws MampException {
        String hasCmpn = inputObject.getParams().get("hasCmpn");
        if (null == hasCmpn || "1".equals(hasCmpn)) { // 有规格
            addMcdsCmpn(inputObject, object);
        }
        // 详情
        addMcdsExt(inputObject, object);
    }

    /* 处理商品规格 */
    private void addMcdsCmpn(InputObject inputObject, OutputObject object) {

        LOGGER.info("调用规格的商品编码为：", inputObject.getParams().get(MCDSID));

        // 调远程 ,然后set参数
        InputObject in = new InputObject();
        Map<String, String> inMap = in.getParams();
        Session session = SecurityUtils.getSubject().getSession();
        String chnlId = session.getAttribute(CHNLID).toString();

        /**此层生成环境网络不通，调用下放到busi层，其余不动
        in.setBusiCode("esb");  // 框架写死不需要再加
        in.setService(RSSERVICE);
        // 不同平台调用接口不同
        in.setMethod("cmpnMethod" + getExtType(chnlId));
        in.addParams("scope", "scope", "GET");
         */

        in.setService(RESOURCESSERVICE);
        in.setMethod(INVOKEREMOTEMETHOD);
        inMap.put(REMOTESERVICE, RSSERVICE);
        inMap.put(REMOTEMETHOD, "cmpnMethod" + getExtType(chnlId));

        inMap.put(CHNLID, chnlId);
        inMap.put(MCDSID, inputObject.getParams().get(MCDSID));
        OutputObject out = super.getOutputObject(in);
        object.setReturnCode(out.getReturnCode());
        object.setReturnMessage(out.getReturnMessage());

        if (ControlConstants.RETURN_CODE.SYSTEM_ERROR.equals(object.getReturnCode())) {
            return;
        }
        String cmpnCn = out.getBean().get("total");
        LOGGER.info("返回的规格总数为：", cmpnCn);
        if (Integer.valueOf(cmpnCn) == 0) {
            return;
        }
        // 有规格
        List<Map<String, String>> cmpnList = out.getBeans();
        String cmpnListJson = JsonUtil.convertObject2Json(cmpnList);
        LOGGER.info("获取到规格信息为：", cmpnListJson);
        inputObject.addParams("cmpnPmStr", "cmpnPmStr", cmpnListJson); // 返回的数据map key 与参数的一致，不需要再转换
    }

    public void addMcdsCmpn() {
        InputObject inputObject = super.getInputObject();
        OutputObject object = new OutputObject();

        addMcdsCmpn(inputObject, object);
    }

    public void addMcdsExt() {
        InputObject in = super.getInputObject();
        OutputObject out = new OutputObject();
        addMcdsExt(in, out);
        super.sendJson(super.convertOutputObject2Json(out));
    }

    /* 处理商品详情扩展 */
    private void addMcdsExt(InputObject inputObject, OutputObject object) {
        LOGGER.info("调用详情的商品编码为：", inputObject.getParams().get(MCDSID));

        // 调远程 ,然后set参数 ，减少参数传递
        InputObject in = new InputObject();
        Map<String, String> inMap = in.getParams();
        Session session = SecurityUtils.getSubject().getSession();
        String chnlId = session.getAttribute(CHNLID).toString();

        /**  此层生成环境网络不通，调用下放到busi层，其余不动
         in.setBusiCode("esb"); // 框架写死不需要再加
        in.setService(RSSERVICE);
        // 不同平台调用接口不同
        in.setMethod("extMethod" + getExtType(chnlId));
        in.addParams("scope", "scope", "GET");
         */
        in.setService(RESOURCESSERVICE);
        in.setMethod(INVOKEREMOTEMETHOD);
        inMap.put(REMOTESERVICE, RSSERVICE);
        inMap.put(REMOTEMETHOD, "extMethod" + getExtType(chnlId));
        inMap.put(CHNLID, chnlId);
        inMap.put(MCDSID, inputObject.getParams().get(MCDSID));
        OutputObject out = super.getOutputObject(in);
        object.setReturnCode(out.getReturnCode());
        object.setReturnMessage(out.getReturnMessage());

        if (ControlConstants.RETURN_CODE.SYSTEM_ERROR.equals(object.getReturnCode())) {
            return;
        }
        if (out.getBean().isEmpty()) {
            LOGGER.warn("详情所在的bean为空", inputObject.getParams().get(MCDSID));
            return;
        }
        String extStr = out.getBean().get(MCDSEXTDMDMTXT);
        inputObject.addParams(MCDSEXTDMDMTXT, MCDSEXTDMDMTXT, extStr);
        inputObject.addParams("extdTypeCd", "extdTypeCd", getExtType(chnlId));
    }

    private static String getExtType(String chnlId) {
        LOGGER.info("用来获取平台来源的渠道id为:", chnlId);
        return chnlId; // 1112 商户管理平台 , 1113 微商城
    }

    /**
     * 将指定格式的Excel文件导入成List
     * Excel 2003
     * 分隔符
     */
    public List<String> exportListFromExcel(String fileContent) throws MampException, IOException {

        InputStream is = ConvertUtil.string2InputStream(fileContent);

        int fileSize = is.available(); // 获取文件大小
        LOGGER.info("fileSize ->", fileSize + "'");
        if (fileSize > Constants.UPLOAD_EXCEL_MAX_SIZE) {
            throw new MampException("上传文件不能超过" + Constants.UPLOAD_EXCEL_MAX_SIZE / 1024 + "M");
        }

        // 通过文件名获取文件扩展名
        String fileName = super.getInputObject().getParams().get("filecontentFileName");
        if (StringUtil.isEmpty(fileName)) {
            throw new MampException("获取文件后缀名失败");
        }
        String extensionName = fileName.substring(fileName.indexOf(".") + 1);

        Workbook workbook;
        if ("xls".equalsIgnoreCase(extensionName)) { // Excel 2003
            workbook = new HSSFWorkbook(is);
        } else if ("xlsx".equalsIgnoreCase(extensionName)) { // Excel 2007
            workbook = new XSSFWorkbook(is);
        } else {
            throw new MampException("文件格式不正确");
        }

        List<String> list = new ArrayList<>();

        Sheet sheet = workbook.getSheetAt(0);

        // 解析公式结果
        FormulaEvaluator evaluator = workbook.getCreationHelper().createFormulaEvaluator();
        // 此处从第二行开始解析即除去表头,第一行不能为空，否则从第三行开始解析
        int minRowIx = sheet.getFirstRowNum() + 1;
        LOGGER.info("import excle minRowIx ->", String.valueOf(minRowIx));
        int maxRowIx = sheet.getLastRowNum();
        LOGGER.info("import excle maxRowIx ->", String.valueOf(maxRowIx));
        for (int rowIx = minRowIx; rowIx <= maxRowIx; rowIx++) {
            Row row = sheet.getRow(rowIx);
            StringBuilder sb = new StringBuilder();

            short minColIx = row.getFirstCellNum();
            short maxColIx = row.getLastCellNum();
            // 不解析maxColIx 这一列，是从0开始的，去除尾列
            for (short colIx = minColIx; colIx < maxColIx; colIx++) {
                Cell cell = row.getCell(new Integer(colIx));
                CellValue cellValue = evaluator.evaluate(cell);
                if (cellValue == null) {
                    continue;
                }
                // 经过公式解析，最后只存在Boolean、Numeric和String三种数据类型，此外就是Error了
                // 其余数据类型，根据官方文档，完全可以忽略http://poi.apache.org/spreadsheet/eval.html
                switch (cellValue.getCellType()) {
                case Cell.CELL_TYPE_NUMERIC:
                    // 这里的日期类型会被转换为数字类型，需要判别后区分处理
                    if (DateUtil.isCellDateFormatted(cell)) {
                        sb.append(SEPARATOR + cell.getDateCellValue());
                    } else {
                        DecimalFormat dfFormat = new DecimalFormat("0");
                        String cellValueStr = dfFormat.format(cellValue.getNumberValue());
                        sb.append(SEPARATOR + cellValueStr);
                    }
                    break;
                case Cell.CELL_TYPE_STRING:
                    sb.append(SEPARATOR + cellValue.getStringValue());
                    break;
                case Cell.CELL_TYPE_FORMULA:
                    break;
                case Cell.CELL_TYPE_BLANK:
                    break;
                case Cell.CELL_TYPE_ERROR:
                    break;
                default:
                    break;
                }
            }
            String str = sb.toString();
            if (str == null || str.trim().length() == 0) {
                continue;
            }
            if (str.length() > 40) {
                throw new MampException("优惠券编码长度不能超过40");
            }
            list.add(str);
        }
        LOGGER.info("Excel  ->", list.toString());
        return list;
    }

    public void uploadImg() {

        OutputObject object = new OutputObject();
        // ftp上传路径
        String remotePath = PropertiesUtil.getString(Constants.SFTP_CONFIG.SFTP_UPLOAD_SRC_PATH);
        String nginxPath = PropertiesUtil.getString(Constants.SFTP_CONFIG.SFTP_UPLOAD_SRC_NGINX);
        String oldFileName = getInputObject().getParams().get("filecontentFileName");

        String fileSuffix = oldFileName.substring(oldFileName.lastIndexOf(".") + 1);
        LOGGER.info("fileSuffix ->", fileSuffix);

        if (!"JPEG".equalsIgnoreCase(fileSuffix) && !"JPG".equalsIgnoreCase(fileSuffix)
                && !"PNG".equalsIgnoreCase(fileSuffix) && !"GIF".equalsIgnoreCase(fileSuffix)) {
            String errMsg = "上传文件格式不正确，只能为JPEG、JPG、PNG、GIF";
            object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.getBean().put(RETURNMSG, errMsg);
            throw new MampException(errMsg);
        }

        String fileContent = getInputObject().getParams().get("filecontent");
        try {
            InputStream is = ConvertUtil.string2InputStream(fileContent);

            int fileSize = is.available(); // 获取文件大小
            LOGGER.info("fileSize ->", fileSize + "'");
            if (fileSize > Constants.UPLOAD_FILE_MAX_SIZE) {
                String errMsg = "上传文件不能超过" + Constants.UPLOAD_FILE_MAX_SIZE / 1024 + "M";
                object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
                object.getBean().put(RETURNMSG, errMsg);
                throw new MampException(errMsg);
            }

            FtpUtil ft = new FtpUtil();

            String tempPath = getServletContext().getRealPath("/data/temp/");
            LOGGER.info("tempPath", tempPath);
            Map<String, String> reMap = ft.compressedAndUploadFile(tempPath, oldFileName, remotePath, nginxPath,
                fileContent, 500, 500);

            String newFileName = reMap.get("newFileName");
            String nginxUrl = reMap.get("nginxUrl");
            String url = reMap.get("url");

            object.getBean().put("url", url); // 页面上展示图片用的完整路径
            object.getBean().put("nginxUrl", nginxUrl); // 相对路径,数据库存
            object.getBean().put("newFileName", newFileName); // 上传的文件名
            object.setReturnCode("0");

        } catch (MampException | IOException e) {

            object.getBean().put("returnCode", ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.setReturnMessage("上传失败");
            LOGGER.warn("MampException", e.getMessage(), e);

        }
        super.sendJson(super.convertOutputObject2Json(object));
    }

    public void regnFromCache() {
        InputObject inputObject = super.getInputObject();
        OutputObject object = new OutputObject();
        object.setReturnCode("0");
        String regnCode = inputObject.getParams().get("regnCode");

        try {
            String regnName = getCacheService().getFromCache(Constants.REDIS_KEY_PERFIX.REGN_MAMP_CODE_ + regnCode);
            object.getBean().put("regnName", regnName);
        } catch (Exception e) {

            object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.setReturnMessage("地区编码和名字从缓存中获取失败" + e.getMessage());
            LOGGER.error("regn2Cache 地区编码和名字从缓存中获取失败", e.getMessage());
            LOGGER.warn("MampException", e.getMessage(), e);

        }
        super.sendJson(super.convertOutputObject2Json(object));
    }

    public void regn2Cache() {
        OutputObject object = super.getOutputObject();
        List<Map<String, String>> list = object.getBeans();
        LOGGER.info("要放入缓存的地区编码和名字:", list.toString());

        try {
            for (Map<String, String> map : list) {
                getCacheService().put2Cache(Constants.REDIS_KEY_PERFIX.REGN_MAMP_CODE_ + map.get("regnCode"),
                    map.get("regnName"));
            }
            object.setReturnMessage(
                    "地区编码和名字放入缓存成功,验证链接(c=10表示编号为10的地区，返回上海)： /front/sh/resources!regnFromCache?uid=g001&c=10");
            object.setBeans(null);
        } catch (Exception e) {

            object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.setReturnMessage("地区编码和名字放入缓存失败" + e.getMessage());
            LOGGER.error("regn2Cache 地区编码和名字放入缓存失败", e.getMessage());
            LOGGER.warn("MampException", e.getMessage(), e);

        }
        super.sendJson(super.convertOutputObject2Json(object));
    }

    public void rsExt2Cache() {
        InputObject inputObject = super.getInputObject();
        OutputObject object = super.getOutputObject();
        object.setReturnCode("0");

        String cmpgnRsId = inputObject.getParams().get("cmpgnRsId");

        try {

            List<Map<String, String>> rgnList = object.getBeans();
            String rgnStrs = JsonUtil.convertObject2Json(rgnList);

            getCacheService().put2Cache(Constants.REDIS_KEY_PERFIX.REGN_MAMP_EXT_ + cmpgnRsId,
                object.getBean().get(MCDSEXTDMDMTXT));

            getCacheService().put2Cache(Constants.REDIS_KEY_PERFIX.REGN_MAMP_RS_RGN_ + cmpgnRsId, rgnStrs);

            object.setReturnMessage("资源编码为" + cmpgnRsId
                + "的详情和销售范围放入缓存成功,获取链接： /front/sh/resources!rsExtFromCache?uid=g001&cmpgnRsId=2016110911502873825"
                + "，删除链接： /front/sh/resources!delRsExtCache?uid=d001&cmpgnRsId=2016110911502873825");
            object.setBeans(null);
        } catch (Exception e) {

            object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.setReturnMessage(cmpgnRsId + "资源详情和销售范围放入缓存失败" + e.getMessage());
            LOGGER.error(cmpgnRsId + "资源详情和销售范围放入缓存失败", e.getMessage());
            LOGGER.warn("MampException", e.getMessage(), e);

        }
        super.sendJson(super.convertOutputObject2Json(object));
    }

    public void delRsExtCache() {
        InputObject inputObject = super.getInputObject();
        OutputObject object = new OutputObject();
        object.setReturnCode("0");
        String cmpgnRsId = inputObject.getParams().get("cmpgnRsId");
        try {
            getCacheService().del(Constants.REDIS_KEY_PERFIX.REGN_MAMP_EXT_ + cmpgnRsId);
            getCacheService().del(Constants.REDIS_KEY_PERFIX.REGN_MAMP_RS_RGN_ + cmpgnRsId);
            object.setReturnMessage("资源编码为" + cmpgnRsId
                + "的详情和销售范围删除成功,验证链接： /front/sh/resources!rsExtFromCache?uid=g001&cmpgnRsId=2016110911502873825");
            object.setBeans(null);
        } catch (Exception e) {

            object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.setReturnMessage(cmpgnRsId + "资源详情和销售范围从缓存删除失败" + e.getMessage());
            LOGGER.error(cmpgnRsId + "资源详情和销售范围从缓存删除失败", e.getMessage());
            LOGGER.warn("MampException", e.getMessage(), e);

        }
        super.sendJson(super.convertOutputObject2Json(object));
    }

    public void rsExtFromCache() {
        InputObject inputObject = super.getInputObject();
        OutputObject object = new OutputObject();
        object.setReturnCode("0");
        String cmpgnRsId = inputObject.getParams().get("cmpgnRsId");

        try {
            String mcdsExtdMdmtxt = getCacheService()
                    .getFromCache(Constants.REDIS_KEY_PERFIX.REGN_MAMP_EXT_ + cmpgnRsId);

            object.getBean().put("rsExt", mcdsExtdMdmtxt);

            String rgnStrs = getCacheService().getFromCache(Constants.REDIS_KEY_PERFIX.REGN_MAMP_RS_RGN_ + cmpgnRsId);

            List<Map<String, String>> rgnList = JsonUtil.convertJson2Object(rgnStrs, List.class);
            object.getBeans().addAll(rgnList);

        } catch (Exception e) {

            object.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            object.setReturnMessage(cmpgnRsId + "资源详情和销售范围从缓存中获取失败" + e.getMessage());
            LOGGER.warn("MampException", e.getMessage(), e);
        }
        super.sendJson(super.convertOutputObject2Json(object));
    }

    public void export() {
        InputObject inputObject = super.getInputObject();
        Map<String, String> paramMap = inputObject.getParams();

        setRsExportParam(paramMap);

        OutputObject outputObject = super.getOutputObject();
        paramMap.put(ExcelUtil.FILENAME, "resourceState.xls"); // 有默认值，可以不设置
        try {
            super.exportExcelUrlToOut(inputObject, outputObject);
        } catch (MampException e) {
            outputObject.setReturnCode(ControlConstants.RETURN_CODE.SYSTEM_ERROR);
            outputObject.setReturnMessage("导出Excel失败" + e.getMessage());
            LOGGER.error("导出Excel失败", e.getMessage(), e);
        }
        super.sendJson(super.convertOutputObject2Json(outputObject));
    }

    private void setRsExportParam(Map<String, String> paramMap) {

        String uid = paramMap.get("uid");

        String headName = "日期,实物发放数量,优惠卷发放数量,虚拟物品发放数量";
        String dataName = "dateStr,giveQty01,giveQty02,giveQty03";
        String cellSize = "50,20,20,20";
        if ("sg001".equals(uid)) {
            headName = "活动编号,活动名称,活动类型,资源名称,资源类型,中奖券码,发放账号,是否发放,发放时间";
            dataName = "cmpgnId,cmpgnNm,cmpgnType,rsNm,rsType,skuNo,userId,ntcSts,crtTime";
            cellSize = "50,30,20,50,20,30,20,20,20";
        }

        paramMap.put(ExcelUtil.EXCEL_HEAD_NAME, headName);
        paramMap.put(ExcelUtil.EXCEL_DATA_NAME, dataName);
        paramMap.put(ExcelUtil.EXCEL_CELL_SIZE, cellSize);
    }

    public void issu() {
        OutputObject object = super.getOutputObject();
        super.sendJson(super.convertOutputObject2Json(object));
    }

}
