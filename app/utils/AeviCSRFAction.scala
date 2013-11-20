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
import scala.concurrent.ExecutionContext.Implicits.global
import javax.crypto.IllegalBlockSizeException
package object AeviSecurity {

    val getCipher = Cipher.getInstance("AES/ECB/PKCS5Padding")

    val getKey: Key = {
        val applicationSecret = current.configuration.getString("application.secret").getOrElse(throw new Exception("application secret is not configured"))

        val sha = MessageDigest.getInstance("SHA-1")
        val trimedKey = Arrays.copyOf(sha.digest(applicationSecret.getBytes("UTF-8")), 16)
        new SecretKeySpec(trimedKey, "AES")
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

object GetAction extends ActionBuilder[Request] {
    def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[SimpleResult]) = {
        request.headers.get("username") match {
            case None => block(request)
            case Some(username) => {
                block(request) map (result => result.withHeaders("token" -> AeviSecurity.encrypt(username)))
            }
        }
    }

}

object PostAction extends ActionBuilder[Request] {
    def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[SimpleResult]) = {
        (request.headers.get("username"), request.headers.get("token")) match {
            case (Some(username), Some(token)) => {
                try {
                    val decryptedToken = Json.parse(AeviSecurity.decrypt(token))

                    ((decryptedToken \ "username").asOpt[String], (decryptedToken \ "expiry").asOpt[Long]) match {
                        case (Some(tokenUsername), Some(tokenExpiry)) => {
                            if (new DateTime(tokenExpiry).isBefore(DateTime.now))
                                Future.successful(BadRequest("The token is expired"))
                            else if (tokenUsername != username)
                                Future.successful(BadRequest("The usernme is invalid"))
                            else {
                                block(request) map (result => result.withHeaders("token" -> AeviSecurity.encrypt(username)))
                            }
                        }
                        case _ => Future.successful(BadRequest("The token is invalid"))
                    }
                } catch {
                    case e: IllegalBlockSizeException => Future.successful(BadRequest("The token is damaged1"))
                }
            }
            case _ => Future.successful(BadRequest("The request header is invalid"))
        }
    }

}

