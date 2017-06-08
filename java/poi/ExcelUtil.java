package com.cmos.mamp.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;

import org.apache.poi.xssf.streaming.SXSSFWorkbook;

import com.ai.frame.bean.InputObject;
import com.ai.frame.bean.OutputObject;
import com.ai.frame.logger.Logger;
import com.ai.frame.logger.LoggerFactory;
import com.cmos.mamp.exception.MampException;
import com.jcraft.jsch.SftpException;

/**
 * 导出Excel工具类以及常量设置
 *
 * @author  穆凯
 * @date  2017年2月17日 下午5:52:59
 *
 *
 */
public class ExcelUtil {

    private static final Logger LOGGER                     = LoggerFactory.getServiceLog(ExcelUtil.class);

    private static final String TOTAL                      = "total";
    public static final String  DOWNURL                    = "url";
    /** 上传sftp的目录，默认为 SFTP_UPLOAD_TMPLT_PATH */
    public static final String  REMOTEPATH                 = "remotePath";
    /** 下载sftp的目录，默认为 SFTP_UPLOAD_TMPLT_NGINX */
    public static final String  NGINXPATH                  = "nginxPath";
    /** 生成的Excel前缀名以及后缀，默认为.xls*/
    public static final String  FILENAME                   = "fileName";
    /**
     * 不重新调用后台服务生成新的分页的最小分页数，
     * 此值不能超过5000，
     * 即 Constants.EXPORT_FILE_LIMIT.PAGE_SIZE
     */
    public static final String  NO_REINK_PAGE_SIZE         = "noReInkPageSize";
    /**
     *不重新调用后台服务生成新的分页的最小分页数5000，
     * 即 Constants.EXPORT_FILE_LIMIT.PAGE_SIZE
     */
    public static final String  DEF_NO_REINK_PAGE_SIZE     = String.valueOf(Constants.EXPORT_FILE_LIMIT.PAGE_SIZE);
    /**
     *不重新调用后台服务生成新的分页的最小分页数5000，
     * 即 Constants.EXPORT_FILE_LIMIT.PAGE_SIZE
     */
    public static final int     INT_DEF_NO_REINK_PAGE_SIZE = Constants.EXPORT_FILE_LIMIT.PAGE_SIZE;
    /** excel的列头：各列名字*/
    public static final String  EXCEL_HEAD_NAME            = "excel_head_cnname";
    /** excel的列头：各列对应的查询结果的字段*/
    public static final String  EXCEL_DATA_NAME            = "excel_data_enname";
    /** excel每列的宽度：数字字符串，不带单位*/
    public static final String  EXCEL_CELL_SIZE            = "excel_data_cellSize";

    /** 不需要再分页查询 */
    public static final String  ISNOINVOKE                 = "isNoInvoke";
    public static final String  TRUESTR                    = "true";
    public static final int     DEF_NULL_VALUE             = -2;

    /**
     * 导入查询的内容到Excel，导出后传到sftp，路径放到bean的downUrl中<br/>
     */
    public static void exportExcel(InputObject inputObject, OutputObject outputObject, List<OutputObject> outList)
            throws MampException, SftpException, IOException {
        if (outList == null || outList.isEmpty()) {
            throw new MampException("没有数据");
        }

        getExcleUrl(inputObject, outputObject, outList);
    }

    /**
     * 先调用此方法，设置分页参数，再调用 exportExcel 方法
     * @author  穆凯
     * @date  2017年2月16日 下午4:12:01
     *
     *
     * @param inputObject
     * @param outputObject
     */
    public static void resetInputPage(InputObject inputObject, OutputObject outputObject) {
        Map<String, String> paramMap = inputObject.getParams();

        String totalStr = outputObject.getBean().get(TOTAL);
        int total = checkTotal(totalStr);
        if (total == DEF_NULL_VALUE || total == 0) {
            paramMap.put(ISNOINVOKE, TRUESTR);
            return;
        }

        // 判断是否需要重新查服务数据，就一页数据不用再调用 begin
        String limitStr = paramMap.get("limit");
        int limit = 0;
        if (StringUtil.isEmpty(limitStr)) {
            limit = INT_DEF_NO_REINK_PAGE_SIZE;
        } else if (StringUtil.isNum(limitStr)) {
            limit = Integer.parseInt(limitStr);
        }

        if (limit > INT_DEF_NO_REINK_PAGE_SIZE) {
            limit = INT_DEF_NO_REINK_PAGE_SIZE;
        }

        if (total <= limit) {
            paramMap.put(ISNOINVOKE, TRUESTR);
            return;
        }
        // 判断是否需要重新查服务数据 end.

        // 获取系统默认的导出分页查询条数
        int pageSize = INT_DEF_NO_REINK_PAGE_SIZE;
        // 计算总页数
        int pageCount = total / pageSize;
        if (total % pageSize > 0) {
            pageCount = pageCount + 1;
        }

        paramMap.put("pageCount", String.valueOf(pageCount));
        paramMap.put("pageSize", String.valueOf(pageSize));

    }

    private static void getExcleUrl(InputObject inputObject, OutputObject outputObject, List<OutputObject> outList)
            throws MampException, SftpException, IOException {

        byte[] bs = writeToExcel(inputObject, outputObject, outList);
        String downUrl = getDownUrl(inputObject, bs);
        outputObject.getBean().put(DOWNURL, downUrl);
    }

    private static void wbToStream(SXSSFWorkbook wb, ByteArrayOutputStream outstream) {
        try {
            wb.write(outstream);
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), "写入EXCEL失败", e);
            throw new MampException(e.getMessage());
        }
    }

    private static byte[] writeToExcel(InputObject inputObject, OutputObject outputObject, List<OutputObject> outList) {

        // 定义临时输出字节流
        ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        // 定义EXCEL POI对象
        SXSSFWorkbook wb = new SXSSFWorkbook();

        // 创建EXCEL列头第一行
        ExcelPOI07Util.createExcel2007(true, wb, outstream, outputObject);

        // 正式写数据
        for (OutputObject obj : outList) {
            ExcelPOI07Util.createExcel2007(false, wb, outstream, obj);
        }

        // 真正写入EXCEL
        wbToStream(wb, outstream);

        closeWb(wb);
        byte[] bs = outstream.toByteArray();
        closeStream(outstream);
        return bs;
    }

    private static void closeWb(SXSSFWorkbook wb) {
        // 关闭POI自定义对象同时清除临时文件资源
        try {
            wb.close();
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), "关闭POI自定义对象失败", e);
            throw new MampException(e.getMessage());
        }
    }

    private static void closeStream(OutputStream outstream) {
        try {
            outstream.close();
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), "关闭输出字节流失败", e);
            throw new MampException(e.getMessage());
        }
    }

    public static String getDownUrl(InputObject inputObject, byte[] bytes)
            throws MampException, SftpException, IOException {

        Map<String, String> paramMap = inputObject.getParams();

        String remotePath = paramMap.get(REMOTEPATH);
        if (StringUtil.isEmpty(remotePath)) {
            remotePath = PropertiesUtil.getString(Constants.SFTP_CONFIG.SFTP_UPLOAD_TMPLT_PATH);
        }
        String nginxPath = paramMap.get(NGINXPATH);
        if (StringUtil.isEmpty(nginxPath)) {
            nginxPath = PropertiesUtil.getString(Constants.SFTP_CONFIG.SFTP_UPLOAD_TMPLT_NGINX);
        }

        String fileName = paramMap.get(FILENAME);
        if (StringUtil.isEmpty(fileName)) {
            fileName = ".xls";
        }
        String downUrl = new FtpUtil().upload(bytes, fileName, remotePath, nginxPath).get(DOWNURL);
        return downUrl;
    }

    private static int checkTotal(String totalStr) {
        if (totalStr == null) {
            return DEF_NULL_VALUE;
        }
        int total = 0;
        try {
            total = Integer.parseInt(totalStr);
        } catch (Exception ex) {
            LOGGER.error("查询导出总数为字符，无法转换为数字", "total:" + totalStr, ex);
            throw new MampException("查询导出总数为字符，无法转换为数字");
        }
        // 获取默认支持导出的最大记录条数
        int maxSize = Constants.EXPORT_FILE_LIMIT.MAX_RECORDS;
        if (total > maxSize) {
            throw new MampException("最大允许导出" + maxSize + "条，请更换查询条件！");
        }

        return total;
    }
}
