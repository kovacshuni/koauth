package com.hunorkovacs.koauth.domain

case class OauthRequest(method: String,
                        urlWithoutParams: String,
                        authorizationHeader: String,
                        urlParams: List[(String, String)],
                        bodyParams: List[(String, String)])

case class EnhancedRequest(method: String,
                           urlWithoutParams: String,
                           urlParams: List[(String, String)],
                           bodyParams: List[(String, String)],
                           oauthParamsList: List[(String, String)],
                           oauthParamsMap: Map[String, String])

object EnhancedRequest {

  def apply(enhancedRequest: EnhancedRequest, oauthParamsList: List[(String, String)]) = {
    new EnhancedRequest(enhancedRequest.method,
      enhancedRequest.urlWithoutParams,
      enhancedRequest.urlParams,
      enhancedRequest.bodyParams,
      oauthParamsList,
      oauthParamsList.toMap)
  }
}
