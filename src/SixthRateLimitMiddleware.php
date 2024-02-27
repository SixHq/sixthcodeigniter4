<?php

namespace Sixth\CodeigniterSdk;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Exception;
use Config\Services;




class SixRateLimiterMiddleware implements FilterInterface
{

    public function before(RequestInterface $request, $arguments = null)
    {
        // Code to run before executing controller methods
        // For example, you can perform authentication or logging here
        try{
            $path = service('uri')->getPath();
            if ($path === '/index.php/' || $path === '/index.php' || $path === 'index.php/') {
                $extractedString = '/';
            } else {
                // If $path is not '/index.php/', perform the replacement
                $extractedString = str_replace('/index.php/', '', $path);
            }
            $editedRoute = preg_replace("/\W+/", "~", $extractedString);


            $config = json_decode($this->processSixthJson($arguments[0]));
            $apikey = $arguments[1];
            $rlConfig = $config->rate_limiter->$editedRoute;

            //get details about the request
            $host = $request->getIPAddress();
            $headers = $request->getHeaders();
            $query_params = $request->getGet();
            $body = $request->getBody();
            if ($rlConfig->is_active){
                $preferred_id = $rlConfig->unique_id;
                $rule_object=[];
                if ($preferred_id === "" or $preferred_id === "host"){
                    $preferred_id = $host;
                }
                else{
                    if ($rlConfig->rate_limit_type === "body"){
                        if ($body !== null) {
                            $preferred_id = json_decode($body)->$preferred_id;
                        }
                        
                    }
                    else if ($rlConfig->rate_limit_type === "header"){
                        $preferred_id = $headers[$preferred_id];
                    }
                    else if ($rlConfig->rate_limit_type === "args"){
                        $preferred_id = $query_params[$preferred_id];
                    }
                    else {
                        $preferred_id = $host;
                    }
                }
                $rule_object["default"] = $preferred_id;
                try{
                    $rate_limit_rules = null;
                    try{
                        $rate_limit_rules = $rlConfig->rate_limit_by_rules;

                    }catch(Exception $e){

                    }
                    if ($rate_limit_rules !== null){
                        $rules = $rlConfig->rate_limit_by_rules;
                        foreach ($rules as $key => $value) {
                            if ($key ==="body"){
                                $rule_object[$key] = $body[$value];
                            }
                            else if ($key ==="header"){
                                $rule_object[$key] = $headers[$value];
                            }
                            else if ($key ==="args"){
                                $rule_object[$key] = $query_params[$value];
                            }
                            else if ($key === "host"){
                                $rule_object[$key] = $host;
                            }
                        }
                    }

                    $final_rule = "";

                    foreach ($rule_object as $key=>$value){
                        $final_rule .= $value;
                    }
                    if ($this->_is_rate_limit_reached($final_rule, $editedRoute, $rlConfig, $apikey)){
                        $this->_send_logs($extractedString, $headers, $body, $query_params, $apikey);
                        $error_payload = [];
                        try{
                            $temp_payload = $rlConfig->error_payload;
                            foreach ($temp_payload as $key){
                                foreach ($key as $newkey => $value){
                                    if($newkey !== "uid"){
                                        $error_payload[$newkey] = $value;
                                    }
                                    
                                }
                            }    
                        }catch(Exception $e){
                            $error_payload["message"]="max_limit_reached";
                        }
                        return Services::response()->setStatusCode(429)->setJSON($error_payload);
                    }
                    
                }catch(Exception $e){
                }
                
            }else{
                
            }
        }
        catch (Exception $e){

        }
            
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Code to run after executing controller methods
        // For example, you can modify the response here
       
    }


    private function processSixthJson($jsonString){
        $json = str_replace("8991928389919283", ":",str_replace('8991928689919286', ',', $jsonString));
        return $json;
    }

    private function _is_rate_limit_reached($final_rule, $route, $rlConfig, $apikey){
        $interval = $rlConfig->interval;
        $body = [];
        $body['route'] = $route;
        $body['interval'] = $interval;
        $body['rate_limit'] = $rlConfig->rate_limit;
        $body['unique_id'] = str_replace("~", ".",$final_rule);
        $body["user_id"] = $apikey;
        $body["is_active"] = true;

        $body = json_encode($body);
        
        $url = "https://backend.withsix.co/rate-limit/enquire-has-reached-rate_limit";
        
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
            return false;
            // Handle error...
        } else {
            // Process the response
          
        }
        $response = json_decode($response, true);
        return  $response["response"];
    }

    private function _send_logs($route, $header, $payload_body, $query, $apikey){
        $body = [];
        $body['header'] = $header;
        $body['user_id'] = $apikey;
        $body['body'] = json_encode($payload_body);
        $body['query_args'] = $query;
        $body['timestamp'] = time();
        $body["attack_type"] = "No Rate Limit Attack";
        $body["cwe_link"] = "https://cwe.mitre.org/data/definitions/770.html";
        $body["status"] = "MITIGATED";
        $body["learn_more_link"] = "https://en.wikipedia.org/wiki/Rate_limiting";
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

}