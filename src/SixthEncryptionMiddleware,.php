<?php

namespace Sixth\CodeigniterSdk;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Exception;
use Config\Services;



class SixEncryptionMiddleware implements FilterInterface
{
    private  $_encryption_enabled = false;
    private $_last_updated;

    public function before(RequestInterface $request, $arguments = null)
    {
        // Code to run before executing controller methods
        // For example, you can perform authentication or logging here
        try{
            $req_body = $request->getbody();
           
        }
        catch (Exception $e){

        }
        

    
        
        
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Code to run after executing controller methods
        // For example, you can modify the response here
        try{
            _update_encryption_details(  $apikey = $arguments[1];)
            if($_encryption_enabled)
            {
            
                $path = service('uri')->getPath();
                if ($path === '/index.php/' || $path === '/index.php' || $path === 'index.php/') {
                    $extractedString = '/';
                } else {
                    // If $path is not '/index.php/', perform the replacement
                    $extractedString = str_replace('/index.php/', '', $path);
                }
                $editedRoute = preg_replace("/\W+/", "~", $extractedString);
                $req_body = $request->getbody();
              ;


            }
           
        }
        catch (Exception $e){

        }
       
    }
    
    function set_body($request, $body) {
        // Define a custom receive function
        function receive() use ($body) {
            return ['type' => 'http.request', 'body' => $body];
        }
    
        // Assign the custom receive function to the request object
        $request->_receive = receive;
    }


    function parse_bools($string) {
        // Decode the input string from bytes to UTF-8
        $string = utf8_decode($string);
    
        // Remove spaces
        $string = str_replace(' ', '', $string);
    
        // Replace occurrences of "true" and "false"
        $string = str_replace('true,', 'True,', $string);
        $string = str_replace(',true', 'True,', $string);
        $string = str_replace('false,', 'False,', $string);
        $string = str_replace(',false', 'False,', $string);
    
        // Evaluate the modified string
        $out = eval('return ' . $string . ';');
    
        // Return the result
        return $out;
    }
    


    private function _send_logs($route, $header, $payload_body, $query, $apikey){
        $body = [];
        $body['header'] = $header;
        $body['user_id'] = $apikey;
        $body['body'] = json_encode($payload_body);
        $body['query_args'] = $query;
        $body['timestamp'] = time();
        $body["attack_type"] = "Encryption Bypass";
        $body["cwe_link"] = "https://cwe.mitre.org/data/definitions/770.html";
        $body["status"] = "MITIGATED";
        $body["learn_more_link"] = "https://en.wikipedia.org/wiki/Encryption";
        $body["route"] = $route;

        $body = json_encode($body);
       
        $url = "https://backend.withsix.co/slack/send_message_to_slack_user";
        
        // Data to be sent in the POST request (in JSON format)
        
        // Initialize cURL session
        $curl = curl_init();

        // Set cURL options
        curl_setopt_array($curl, array(
            CURLOPT_URL => $url,                    // URL to send the request to
            CURLOPT_RETURNTRANSFER => true,         // Return the response as a string
            CURLOPT_POST => true,                   // Set request method to POST
            CURLOPT_POSTFIELDS => $body,        // Set the POST data
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/json',   // Set the content type to JSON
                'Content-Length: ' . strlen($body) // Set content length
            )
        ));

        // Execute cURL request and get the response
        $response = curl_exec($curl);

    
        // Check for errors
        if (curl_errno($curl)) {
            $error = curl_error($curl);
            // Handle error...
        } else {
            // Process the response
        
        }
        
    }

    private function _update_encryption_details($apikey) {
        $timestamp = time();
        if ($timestamp - $this->_last_updated < 10) {
            return;
        }
        $url = "https://backend.withsix.co/encryption-service/get-encryption-setting-for-user?user_id=" . $this->_apikey;
        $response = file_get_contents($url);
        if ($response !== false) {
            $data = json_decode($response, true);
            $this->$_encryption_enabled = $data["enabled"];
            $this->$_last_updated = $timestamp;

        } else {
            $this->_encryption_enabled = false;
        }
    }

}
?>