package utils

import play.api.mvc._
import scala.concurrent.Future
import java.security.SignatureException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.util.UUID
import org.joda.time.DateTime
import org.joda.time.Period
import play.api.Play.current
import org.apache.commons.codec.binary.Base64
import play.api.Logger
import play.api.mvc.BodyParsers._
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher
import java.security.MessageDigest
import java.util.Arrays
import java.security.Key
import play.api.libs.json.Json
import play.api.mvc.Results._
import play.api.libs.json.JsValue
import play.api.libs.json.JsSuccess
import play.api.libs.json.JsError

package object AeviSecurity {
    val getKey: Key = {
        val applicationSecret = current.configuration.getString("application.secret").getOrElse(throw new Exception("application secret is not configured"))

        val sha = MessageDigest.getInstance("SHA-1")
        val trimedKey = Arrays.copyOf(sha.digest(applicationSecret.getBytes("UTF-8")), 16)
        new SecretKeySpec(trimedKey, "AES")
    }
    val getCipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
}

class CsrfRequest[A](val username: String, request: Request[A]) extends WrappedRequest[A](request)

object GetAction extends ActionBuilder[Request] {
    def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[SimpleResult]) = {
        if (request.headers.get("token") == None) {
            val username = request.headers.get("username").get
            val token = encrypt(username)
            println("token => " + token)
        }
        block(request)
    }

    def encrypt(username: String): String = {
        val nounce = UUID.randomUUID().toString
        val expiry = DateTime.now.plus(Period.minutes(15))
        val payload = Json.stringify(Json.obj("username" -> username, "expiry" -> expiry, "nounce" -> nounce)).getBytes("UTF8")

        val cipher = AeviSecurity.getCipher
        val key = AeviSecurity.getKey
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val cipherText = cipher.doFinal(payload)
        new String(Base64.encodeBase64(cipherText))
    }
}

object PostAction extends ActionBuilder[CsrfRequest] {
    def invokeBlock[A](request: Request[A], block: (CsrfRequest[A]) => Future[SimpleResult]) = {
        val decrypted = decrypt(request.headers.get("token").get)
        println("decrypted => " + decrypted)

        val username = (Json.parse(decrypted) \ "username").as[String]
        val expiry = (Json.parse(decrypted) \ "expiry").as[Long]
        println("username => " + username)
        println("expiry => " + expiry)
        val jsPayload = request.body.asInstanceOf[AnyContentAsJson].asJson.get
        val jsUsername = (jsPayload \ "username").asOpt[String].get

        if (new DateTime(expiry).isBefore(DateTime.now))
            Future.successful(BadRequest("The token is expired"))
        else if (jsUsername != username)
            Future.successful(BadRequest("The usernme is invalid"))
        else {
            block(new CsrfRequest(username, request))
        }
    }

    def decrypt(token: String) = {
        val key = AeviSecurity.getKey

        val cipher = AeviSecurity.getCipher
        cipher.init(Cipher.DECRYPT_MODE, key);

        val decoded = Base64.decodeBase64(token.getBytes)
        val newPlainText = cipher.doFinal(decoded);
        System.out.println("Finish decryption: ");

        new String(newPlainText, "UTF8")

    }
}

