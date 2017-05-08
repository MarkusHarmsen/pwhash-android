package de.markus.pwhash;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.app.Activity;
import android.text.InputFilter;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MainActivity extends Activity {
    private final int HASH_MAX_RESULT_LENGTH        = 26;
    @SuppressWarnings("FieldCanBeLocal")
    private final int HASH_DEFAULT_RESULT_LENGTH    = 16;

    private EditText mEditTag;
    private EditText mEditPassword;
    private EditText mEditLength;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mEditTag        = (EditText) findViewById(R.id.edit_tag);
        mEditPassword   = (EditText) findViewById(R.id.edit_password);
        mEditLength     = (EditText) findViewById(R.id.edit_length);

        // Set max and min length
        mEditLength.setFilters(new InputFilter[]{new InputFilterMinMax(1, HASH_MAX_RESULT_LENGTH)});
        mEditLength.setText(String.valueOf(HASH_DEFAULT_RESULT_LENGTH));

        findViewById(R.id.btn_copy_hash).setOnClickListener(onCopyHashClickListener);
        findViewById(R.id.btn_clear_clipboard).setOnClickListener(onClearClipboardClickListener);
    }

    private final View.OnClickListener onCopyHashClickListener = new View.OnClickListener() {

        @Override
        public void onClick(View view) {
            @SuppressWarnings("ConstantConditions")
            String data = mEditTag.getText().toString();
            @SuppressWarnings("ConstantConditions")
            String key  = mEditPassword.getText().toString();
            @SuppressWarnings("ConstantConditions")
            int length  = Integer.valueOf(mEditLength.getText().toString());

            if(key.length() == 0) {
                Toast.makeText(MainActivity.this, MainActivity.this.getResources().getString(R.string.alert_key_is_zero), Toast.LENGTH_SHORT).show();
                return;
            }

            // Delete password
            mEditPassword.setText("");

            String code = generateHash(data, key, length);

            // Copy to clipboard
            setClipboard(code);

            Toast.makeText(MainActivity.this, MainActivity.this.getResources().getString(R.string.alert_hash_copied), Toast.LENGTH_SHORT).show();
        }
    };

    private final View.OnClickListener onClearClipboardClickListener = new View.OnClickListener() {

        @Override
        public void onClick(View view) {
            setClipboard("");
        }
    };

    // Copy to clipboard
    private void setClipboard(String value) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(MainActivity.this.getResources().getString(R.string.app_name), value);
        clipboard.setPrimaryClip(clip);
    }

    /*
     * Build HMAC SHA1(key, data) and encode the result base64.
     * Return a substring(0, length), with 0 < length <= 26.
     *
     * Compatible with hashapass (http://hashapass.com/en/index.html) when using a length of 8.
     *
     * Why only 26 chars?
     *   When encode base64, we can store more information in a string as we could in a base16 one (SHA1 hash).
     *   Therefore the base64 encoded string uses padding ('A's) to extend the length.
     */
    private String generateHash(final String data, final String key, int length) {
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }

        SecretKeySpec secret;
        try {
            secret = new SecretKeySpec(key.getBytes("UTF-8"), mac.getAlgorithm());
        } catch (UnsupportedEncodingException e) {
            return null;
        }

        try {
            mac.init(secret);
        } catch (InvalidKeyException e) {
            return null;
        }

        byte[] digest = mac.doFinal(data.getBytes());

        // Base64 encode
        String code = Base64.encodeToString(digest, Base64.DEFAULT);

        // Limit length (0 < length <= 26)
        length = length < 1           ? 1 : length;
        length = length > HASH_MAX_RESULT_LENGTH ? HASH_MAX_RESULT_LENGTH : length;

        // Set length
        code = code.substring(0, length);

        return code;
    }
    
}
