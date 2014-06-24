package com.hunorkovacs.koauth.domain

case class OauthRequest(authorizationHeader: String,
                        urlWithoutParams: String,
                        method: String,
                        queryString: Map[String, Seq[String]])

case class EnhancedRequest(authorizationHeader: String,
                           urlWithoutParams: String,
                           method: String,
                           queryString: Map[String, Seq[String]],
                           oauthParamsList: List[(String, String)],
                           oauthParamsMap: Map[String, String])

object EnhancedRequest {

  def apply(oauthRequest: OauthRequest,
            oauthParamsList: List[(String, String)],
            oauthParamsMap: Map[String, String]): EnhancedRequest = {
    new EnhancedRequest(oauthRequest.authorizationHeader,
                        oauthRequest.urlWithoutParams,
                        oauthRequest.method,
                        oauthRequest.queryString,
                        oauthParamsList,
                        oauthParamsMap)
  }
}
