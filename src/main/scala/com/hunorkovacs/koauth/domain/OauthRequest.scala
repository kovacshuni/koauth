package com.hunorkovacs.koauth.domain

case class OauthRequest(authorizationHeader: String,
                        urlWithoutParams: String,
                        method: String,
                        queryString: Map[String, Seq[String]])

case class EnhancedRequest(override val authorizationHeader: String,
                           override val urlWithoutParams: String,
                           override val method: String,
                           override val queryString: Map[String, Seq[String]],
                           oauthParamsList: List[(String, String)],
                           oauthParamsMap: Map[String, String])
  extends OauthRequest(authorizationHeader, urlWithoutParams, method, queryString)

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
