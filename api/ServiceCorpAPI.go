package api

var SERVICE_CORP_API_TYPE = map[string][]string{
	"GET_CORP_TOKEN":         {"/cgi-bin/service/get_corp_token?suite_access_token=SUITE_ACCESS_TOKEN", "POST"},
	"GET_SUITE_TOKEN":        {"/cgi-bin/service/get_suite_token", "POST"},
	"GET_PRE_AUTH_CODE":      {"/cgi-bin/service/get_pre_auth_code?suite_access_token=SUITE_ACCESS_TOKEN", "GET"},
	"SET_SESSION_INFO":       {"/cgi-bin/service/set_session_info?suite_access_token=SUITE_ACCESS_TOKEN", "POST"},
	"GET_PERMANENT_CODE":     {"/cgi-bin/service/get_permanent_code?suite_access_token=SUITE_ACCESS_TOKEN", "POST"},
	"GET_AUTH_INFO":          {"/cgi-bin/service/get_auth_info?suite_access_token=SUITE_ACCESS_TOKEN", "POST"},
	"GET_ADMIN_LIST":         {"/cgi-bin/service/get_admin_list?suite_access_token=SUITE_ACCESS_TOKEN", "POST"},
	"GET_USER_INFO_BY_3RD":   {"/cgi-bin/service/getuserinfo3rd?suite_access_token=SUITE_ACCESS_TOKEN", "GET"},
	"GET_USER_DETAIL_BY_3RD": {"/cgi-bin/service/getuserdetail3rd?suite_access_token=SUITE_ACCESS_TOKEN", "POST"},
}

// ServiceCorpAPI TODO
type ServiceCorpAPI struct {
}
