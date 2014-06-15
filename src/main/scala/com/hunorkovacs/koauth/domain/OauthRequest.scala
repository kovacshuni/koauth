package com.hunorkovacs.koauth.domain

case class OauthRequest(authorizationHeader: String,
                        urlWithoutParams: String,
                        method: String,
                        queryString: Map[String, Seq[String]])
