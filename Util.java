package tools;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import wxpay.common.Configure;

public class Util {
	protected static final Logger logger = LoggerFactory.getLogger(Util.class);

	/**
	 * 取得分隔后值
	 * 
	 * @param strVaue
	 *            值
	 * @param flag
	 *            标记
	 * @return 值数组
	 */
	public static String[] stringToKenizer(String strVaue, String flag) {
		StringTokenizer st = new StringTokenizer(strVaue, flag);

		int len = st.countTokens();
		String[] strs = new String[len];

		for (int k = 0; k < len; k++) {
			strs[k] = st.nextToken();
		}

		return strs;
	}

	public static String getStringFromArray(String[] strData) {
		StringBuffer sbResult = new StringBuffer("");
		if (strData == null)
			return sbResult.toString();

		for (int i = 0; i < strData.length; i++) {
			if (strData[i] != null && strData[i].trim().length() > 0)
				sbResult.append(",").append(strData[i].trim());
		}

		return sbResult.toString();
	}

	/**
	 * 计算MD5
	 * 
	 * @param input
	 * @return
	 */
	public static String getMD5(String input) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] messageDigest = md.digest(input.getBytes("UTF-8"));
			BigInteger number = new BigInteger(1, messageDigest);
			String hashtext = number.toString(16);
			// Now we need to zero pad it if you actually want the full 32
			// chars.
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}
			return hashtext.toUpperCase();
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 删除当天之外的文件
	 * 
	 * @throws Exception
	 * @author lizhl
	 */
	public static void removeFolder(String dateValue, String picPath)
			throws Exception {
		File fileOut = new File(picPath);
		File[] files = fileOut.listFiles();
		for (int i = 0; i < files.length; i++) {
			File file = files[i];
			if (file.getName().startsWith(dateValue)) {// 当天生成的文件不做操作
			} else {// 非今天生成的文件都删除
				if (file.exists()) {// 验证文件是否存在
					file.delete();
				}
			}
		}
	};

	public static String filterOffUtf8Mb4(String text)
			throws UnsupportedEncodingException {
		byte[] bytes = text.getBytes("utf-8");
		ByteBuffer buffer = ByteBuffer.allocate(bytes.length);
		int i = 0;
		while (i < bytes.length) {
			short b = bytes[i];
			if (b > 0) {
				buffer.put(bytes[i++]);
				continue;
			}

			b += 256;

			if (((b >> 5) ^ 0x6) == 0) {
				buffer.put(bytes, i, 2);
				i += 2;
			} else if (((b >> 4) ^ 0xE) == 0) {
				buffer.put(bytes, i, 3);
				i += 3;
			} else if (((b >> 3) ^ 0x1E) == 0) {
				i += 4;
			} else if (((b >> 2) ^ 0x3E) == 0) {
				i += 5;
			} else if (((b >> 1) ^ 0x7E) == 0) {
				i += 6;
			} else {
				buffer.put(bytes[i++]);
			}
		}
		buffer.flip();
		return new String(buffer.array(), "utf-8");
	}

	public static void writeOk(Map<String, Object> resMap) {
		resMap.put("status", "ok");
	}

	public static void writeError(Map<String, Object> resMap) {
		resMap.put("status", "error");
	}

	public static void writeSuccess(Map<String, Object> resMap) {
		resMap.put("message", "success");
	}

	public static void writeFail(Map<String, Object> resMap) {
		resMap.put("message", "系统错误");
	}

	/**
	 * 慎用，有覆盖的风险 xsy 2016年8月25日 下午8:16:38
	 * 
	 * @param resMap
	 * @param data
	 */
	public static void writeResultData(Map<String, Object> resMap, Object data) {
		resMap.put("resultData", data);
	}

	/***************************** 微信授权 **********************************/
	/**
	 * （微信）检验授权凭证（access_token）是否有效 xsy 2016年8月25日 上午13:17:36
	 * 
	 * @param pCode
	 * @return 正确的JSON返回结果： { "errcode":0,"errmsg":"ok"} 错误时的JSON返回示例： {
	 *         "errcode":40003,"errmsg":"invalid openid"}
	 */
	public static JSONObject checkWxAccessTokenValidation(String access_token,
			String openid) {
		String urlstr = "https://api.weixin.qq.com/sns/auth?access_token="
				+ access_token + "&openid=" + openid;
		JSONObject result = HttpRequestUtils.httpGet(urlstr,null);
		return result;
	}

	/**
	 * （微信）通过授权code换取网页授权access_token xsy 2016年8月25日 上午13:17:36
	 * 
	 * @param pCode
	 * @return 正确的JSON返回结果： { "access_token":"ACCESS_TOKEN", "expires_in":7200,
	 *         "refresh_token":"REFRESH_TOKEN", "openid":"OPENID",
	 *         "scope":"SCOPE" } 错误时微信会返回JSON数据:
	 *         {"errcode":40029,"errmsg":"invalid code"}
	 */
	public static JSONObject getAccessTokenBycode(String code) {
		String urlstr = "https://api.weixin.qq.com/sns/oauth2/access_token?appid="
				+ Configure.getAppid(0)
				+ "&secret="
				+ Configure.getAppSecret(0)
				+ "&code="
				+ code
				+ "&grant_type=authorization_code";
		// JSONObject result = HttpRequestUtils.httpGet(urlstr, null);
		JSONObject result = HttpRequestUtils.httpGet(urlstr, null);
		return result;
	}

	/**
	 * （微信）使用refresh_token刷新access_token（如果需要） xsy 2016年8月25日 上午13:17:36
	 * 
	 * @param pCode
	 * @return 正确的JSON返回结果： { "access_token":"ACCESS_TOKEN", "expires_in":7200,
	 *         "refresh_token":"REFRESH_TOKEN", "openid":"OPENID",
	 *         "scope":"SCOPE" } 错误时微信会返回JSON数据:
	 *         {"errcode":40029,"errmsg":"invalid code"}
	 */
	public static JSONObject refreshAccessToken(String refresh_token) {
		String urlstr = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid="
				+ Configure.getAppid(0)
				+ "&grant_type=refresh_token&refresh_token= " + refresh_token;
		JSONObject result = HttpRequestUtils.httpGet(urlstr, null);
		return result;
	}

	/**
	 * （微信）拉取用户信息(需scope为 snsapi_userinfo) xsy 2016年8月25日 上午13:17:36
	 * 
	 * @param pCode
	 * @return 正确的JSON返回结果： { "openid":" OPENID", " nickname": NICKNAME,
	 *         "sex":"1", "province":"PROVINCE" "city":"CITY",
	 *         "country":"COUNTRY", "headimgurl":
	 *         "http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQ
	 *         Q 4eMsv84eavHiaiceqxibJxCfHe/46", "privilege":[ "PRIVILEGE1"
	 *         "PRIVILEGE2" ], "unionid": "o6_bmasdasdsad6_2sgVt7hMZOPfL" }
	 *         错误时微信会返回JSON数据: {"errcode":40003,"errmsg":" invalid openid "}
	 */
	public static JSONObject getWxUserInfo(String access_token, String openid) {
		String urlstr = "https://api.weixin.qq.com/sns/userinfo?access_token="
				+ access_token + "&openid=" + openid + "&lang=zh_CN";
		JSONObject result = HttpRequestUtils.httpGet(urlstr, null);
		return result;
	}

	/**
	 * （微信分享）获取access_token xsy 2016年9月30日 上午13:17:36
	 * 
	 * @param pCode
	 * @return 正确的JSON返回结果： { "access_token":
	 *         "KVltWpKc3zlXyOb1DMFdChg34s2hXvfwHUZDsiOOmSlmArpH2yMt1YdcnEJ74dWfnpNQz4VhDJcWKUXtGfn5rg3ifAex1wcttyxCnXGjVGMRJXfAAAZRF"
	 *         "expires_in": 7200 }
	 */
	public static JSONObject getAccessToken() {
		String urlstr = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid="
				+ Configure.getAppid(0)
				+ "&secret="
				+ Configure.getAppSecret(0);
		JSONObject result = HttpRequestUtils.httpGet(urlstr,null);
		return result;
	}

	/**
	 * （微信分享）获取jsapi_ticket xsy 2016年9月30日 上午13:17:36
	 * 
	 * @param pCode
	 * @return 正确的JSON返回结果： { "errcode": 0 "errmsg": "ok" "ticket":
	 *         "kgt8ON7yVITDhtdwci0qeZ2QPi1Jdtnv8l6M4R02OU9P2lTJtAeh2z2h0abYVOMm9OUJ8_kTskDaFkLxyAI3mA"
	 *         "expires_in": 7200 }
	 */
	public static JSONObject getJsapiTicket(String access_token) {
		String urlstr = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token="
				+ access_token + "&type=jsapi";
		JSONObject result = HttpRequestUtils.httpGet(urlstr,null);
		return result;
	}

	/**
	 * （微信小程序）通过授权code 换取 session_key和openid xsy 2017年6月22日 上午13:17:36
	 * 
	 * @param pCode
	 * @return 
	 *         正确的JSON返回结果：{"session_key":"LUT8NBW3dU9O+6Bb5TfeLQ==","expires_in"
	 *         :7200,"openid":"oxk3v0I8VLxA4XKrfwVVTnKyzRe0"} 错误时微信会返回JSON数据:
	 *         {"errcode":40029,"errmsg":"invalid code"}
	 */
	public static JSONObject getSessionKeyBycode(String code) {
		String urlstr = "https://api.weixin.qq.com/sns/jscode2session?appid="
				+ Configure.getAppid(1) + "&secret="
				+ Configure.getAppSecret(1) + "&js_code=" + code
				+ "&grant_type=authorization_code";
		JSONObject result = HttpRequestUtils.httpGet(urlstr,null);
		return result;
	}

	/***************************** 微信授权 **********************************/

	/**
	 * 提供精确的乘法运算。
	 * 
	 * @param v1
	 *            被乘数
	 * @param v2
	 *            乘数
	 * @return 两个参数的积
	 */
	public static BigDecimal mul(BigDecimal b1, int quantity) {
		BigDecimal b2 = new BigDecimal(quantity);
		BigDecimal result = new BigDecimal(b1.multiply(b2).doubleValue())
				.setScale(2, BigDecimal.ROUND_HALF_UP);
		return result;
	}

	/**
	 * 提供精确的乘法运算。
	 * 
	 * @param v1
	 *            被乘数
	 * @param v2
	 *            乘数
	 * @return 两个参数的积
	 */
	public static BigDecimal mulBd(BigDecimal b1, int quantity) {
		BigDecimal b2 = new BigDecimal(quantity);
		BigDecimal result = new BigDecimal(b1.multiply(b2).doubleValue())
				.setScale(4, BigDecimal.ROUND_HALF_UP);
		return result;
	}

	/**
	 * 提供精确的乘法运算。
	 * 
	 * @param v1
	 *            被乘数
	 * @param v2
	 *            乘数
	 * @return 两个参数的积
	 */
	public static BigDecimal mul(BigDecimal b1, BigDecimal b2) {
		return b1.multiply(b2).setScale(2, BigDecimal.ROUND_HALF_UP);
	}

	/**
	 * 提供精确的乘法运算。 3精度
	 * 
	 * @param v1
	 *            被乘数
	 * @param v2
	 *            乘数
	 * @return 两个参数的积
	 */
	public static BigDecimal mul4Precise(BigDecimal b1, BigDecimal b2) {
		return b1.multiply(b2).setScale(4, BigDecimal.ROUND_HALF_UP);
	}

	/**
	 * 提供精确的加法运算。
	 * 
	 * @param v1
	 *            被加数
	 * @param v2
	 *            加数
	 * @return 两个参数的和
	 */
	public static BigDecimal add(BigDecimal b1, Integer v2) {
		BigDecimal b2 = new BigDecimal(v2);
		return b1.add(b2).setScale(2, BigDecimal.ROUND_HALF_UP);
	}

	/**
	 * 提供精确的除法运算。
	 * 
	 * @param v1
	 *            被加数
	 * @param v2
	 *            加数
	 * @return 两个参数的和
	 */
	public static BigDecimal divideOfInt(Integer a, Integer b) {
		if (a == null || b == null || b == 0) {
			return new BigDecimal(0);
		}
		BigDecimal af = new BigDecimal(a);
		BigDecimal bf = new BigDecimal(b);
		return af.divide(bf, 2, RoundingMode.HALF_UP);
	}

	/**
	 * 提供精确的Long型金额（分）转成BigDecimal型金额(元)。
	 * 
	 * @param v1
	 *            被除数
	 * @param v2
	 *            除数
	 * @return 以元为单位的金额
	 */
	public static BigDecimal divideOfLong2BigDecimal(Long a, Long b) {
		if (a == null || b == null || b == 0) {
			return new BigDecimal(0);
		}
		BigDecimal af = new BigDecimal(a);
		BigDecimal bf = new BigDecimal(b);
		return af.divide(bf, 2, BigDecimal.ROUND_HALF_UP);
	}

	// 高德转百度（火星坐标gcj02ll–>百度坐标bd09ll）
	public static double[] gaoDeToBaidu(double gd_lon, double gd_lat) {
		double[] bd_lat_lon = new double[2];
		double PI = 3.14159265358979324 * 3000.0 / 180.0;
		double x = gd_lon, y = gd_lat;
		double z = Math.sqrt(x * x + y * y) + 0.00002 * Math.sin(y * PI);
		double theta = Math.atan2(y, x) + 0.000003 * Math.cos(x * PI);
		bd_lat_lon[0] = z * Math.cos(theta) + 0.0065;
		bd_lat_lon[1] = z * Math.sin(theta) + 0.006;
		return bd_lat_lon;
	}

	// 百度转高德（百度坐标bd09ll–>火星坐标gcj02ll）
	public static double[] bdToGaoDe(double bd_lat, double bd_lon) {
		double[] gd_lat_lon = new double[2];
		double PI = 3.14159265358979324 * 3000.0 / 180.0;
		double x = bd_lon - 0.0065, y = bd_lat - 0.006;
		double z = Math.sqrt(x * x + y * y) - 0.00002 * Math.sin(y * PI);
		double theta = Math.atan2(y, x) - 0.000003 * Math.cos(x * PI);
		gd_lat_lon[0] = z * Math.cos(theta);
		gd_lat_lon[1] = z * Math.sin(theta);
		return gd_lat_lon;
	}

	/**
	 * 提供精确的减法运算。
	 * 
	 * @param v1
	 *            被减数
	 * @param v2
	 *            减数
	 * @return 两个参数的差
	 */
	public static BigDecimal subtract(BigDecimal v1, BigDecimal v2) {
		if (v1 == null || v2 == null) {
			return v1;
		}

		return v1.subtract(v2);
	}

	// //生成密码
	// public static void main(String[] args) {
	// for (int i = 1; i < 77; i++) {
	// String s="linjia";
	// if(i<10){
	// s=s+"0";
	// }
	// s=s+i;
	// System.out.println(s+":######:"+getMD5(s));
	// }
	// }

	private final static String[] hex = { "00", "01", "02", "03", "04", "05",
			"06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10",
			"11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B",
			"1C", "1D", "1E", "1F", "20", "21", "22", "23", "24", "25", "26",
			"27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", "30", "31",
			"32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C",
			"3D", "3E", "3F", "40", "41", "42", "43", "44", "45", "46", "47",
			"48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52",
			"53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D",
			"5E", "5F", "60", "61", "62", "63", "64", "65", "66", "67", "68",
			"69", "6A", "6B", "6C", "6D", "6E", "6F", "70", "71", "72", "73",
			"74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E",
			"7F", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89",
			"8A", "8B", "8C", "8D", "8E", "8F", "90", "91", "92", "93", "94",
			"95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
			"A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA",
			"AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2", "B3", "B4", "B5",
			"B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", "C0",
			"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB",
			"CC", "CD", "CE", "CF", "D0", "D1", "D2", "D3", "D4", "D5", "D6",
			"D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1",
			"E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC",
			"ED", "EE", "EF", "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
			"F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF" };
	private final static byte[] val = { 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x00, 0x01,
			0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
			0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F };

	public static String escape(String s) {
		StringBuffer sbuf = new StringBuffer();
		int len = s.length();
		for (int i = 0; i < len; i++) {
			int ch = s.charAt(i);
			if (ch == ' ') { // space : map to '+'
				sbuf.append('+');
			} else if ('A' <= ch && ch <= 'Z') { // 'A'..'Z' : as it was
				sbuf.append((char) ch);
			} else if ('a' <= ch && ch <= 'z') { // 'a'..'z' : as it was
				sbuf.append((char) ch);
			} else if ('0' <= ch && ch <= '9') { // '0'..'9' : as it was
				sbuf.append((char) ch);
			} else if (ch == '-'
					|| ch == '_' // unreserved : as it was
					|| ch == '.' || ch == '!' || ch == '~' || ch == '*'
					|| ch == '/' || ch == '(' || ch == ')') {
				sbuf.append((char) ch);
			} else if (ch <= 0x007F) { // other ASCII : map to %XX
				sbuf.append('%');
				sbuf.append(hex[ch]);
			} else { // unicode : map to %uXXXX
				sbuf.append('%');
				sbuf.append('u');
				sbuf.append(hex[(ch >>> 8)]);
				sbuf.append(hex[(0x00FF & ch)]);
			}
		}
		return sbuf.toString();
	}

	public static String unescape(String s) {
		StringBuffer sbuf = new StringBuffer();
		int i = 0;
		int len = s.length();
		while (i < len) {
			int ch = s.charAt(i);
			if (ch == '+') { // + : map to ' '
				sbuf.append(' ');
			} else if ('A' <= ch && ch <= 'Z') { // 'A'..'Z' : as it was
				sbuf.append((char) ch);
			} else if ('a' <= ch && ch <= 'z') { // 'a'..'z' : as it was
				sbuf.append((char) ch);
			} else if ('0' <= ch && ch <= '9') { // '0'..'9' : as it was
				sbuf.append((char) ch);
			} else if (ch == '-'
					|| ch == '_' // unreserved : as it was
					|| ch == '.' || ch == '!' || ch == '~' || ch == '*'
					|| ch == '/' || ch == '(' || ch == ')') {
				sbuf.append((char) ch);
			} else if (ch == '%') {
				int cint = 0;
				if ('u' != s.charAt(i + 1)) { // %XX : map to ascii(XX)
					cint = (cint << 4) | val[s.charAt(i + 1)];
					cint = (cint << 4) | val[s.charAt(i + 2)];
					i += 2;
				} else { // %uXXXX : map to unicode(XXXX)
					cint = (cint << 4) | val[s.charAt(i + 2)];
					cint = (cint << 4) | val[s.charAt(i + 3)];
					cint = (cint << 4) | val[s.charAt(i + 4)];
					cint = (cint << 4) | val[s.charAt(i + 5)];
					i += 5;
				}
				sbuf.append((char) cint);
			}
			i++;
		}
		return sbuf.toString();
	}

	// emoji表情过滤
	public static String filterEmoji(String source) {
		if (source != null) {
			Pattern emoji = Pattern
					.compile(
							"[\ud83c\udc00-\ud83c\udfff]|[\ud83d\udc00-\ud83d\udfff]|[\u2600-\u27ff]",
							Pattern.UNICODE_CASE | Pattern.CASE_INSENSITIVE);
			Matcher emojiMatcher = emoji.matcher(source);
			if (emojiMatcher.find()) {
				source = emojiMatcher.replaceAll("");
				return source;
			}
			return source;
		}
		return source;
	}

	// 请求信息获取
	public static void getReqInfo(HttpServletRequest request) {
		String head = request.getHeader("Content-Type");
		String method = request.getMethod();
		System.out.println("head****" + head);
		System.out.println("method****" + method);

		// 头部信息
		Enumeration headerNames = request.getHeaderNames();
		String headers = "";
		while (headerNames.hasMoreElements()) {
			String key = (String) headerNames.nextElement();
			String value = request.getHeader(key);
			headers = headers + key + ":" + value + "\n";
		}
		System.out.println("**************************");
		System.out.println("headers:" + headers);
		System.out.println("**************************");
		System.out.println("queryString:" + request.getQueryString());

		Enumeration paramNames = request.getParameterNames();
		String params = "";
		while (paramNames.hasMoreElements()) {
			String paramName = (String) paramNames.nextElement();

			String[] paramValues = request.getParameterValues(paramName);
			if (paramValues.length == 1) {
				String paramValue = paramValues[0];
				if (paramValue.length() != 0) {
					params = params + paramName + ":" + paramValues + "\n";
				}
			}
		}
		System.out.println("------------------------------");
		System.out.println("params:" + params);
		System.out.println("------------------------------");
	}

	public static String parseEncodeParam(String param) {
		String parseVal = "";
		try {
			if (ComTools.isEmpty(param)) {
				return parseVal;
			} else {
				parseVal = new String(param.getBytes("ISO-8859-1"), "UTF-8");
				return parseVal;
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return parseVal;
		}
	}

	public static boolean ifContainChinese(String param) {
		boolean flag = false;
		String regEx = "[\u4e00-\u9fa5]";
		Pattern pat = Pattern.compile(regEx);
		Matcher matcher = pat.matcher(param);
		if (matcher.find()) {
			flag = true;
		}
		return flag;
	}

	// 生成1-10随机整数
	public static int getRandInt() {
		Random rnd = new Random();
		int k = rnd.nextInt(10) + 1;
		return k;
	}

	// 获取当前时间10位时间戳
	public static String getNowTimestamp() {
		Long time = new Date().getTime();
		String str = time / 1000 + "";
		return str;
	}

	/**
	 * 正整数校验
	 */
	public static boolean checkMathNum(String num) {
		if (num == null || num == "" || num == " ") {
			return false;
		}
		String regex = "^\\+?[1-9][0-9]*$";
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(num);
		return matcher.matches();
	}

}
