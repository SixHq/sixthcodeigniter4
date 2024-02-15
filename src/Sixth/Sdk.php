<?php
namespace Sixhq\Sixthcodeigniter4;


use CodeIgniter\Commands\Utilities\Routes\FilterFinder;
use Exception;
use Sixhq\Sixthcodeigniter4\SixRateLimiterMiddleware;

use Config\Services;




class Sixth {
    private $_apikey;
    private $_app;
    private $_config;

    public function __construct($apikey) {
        $this->_apikey = $apikey;
    }

    public function init() {
        $_base_url = "https://backend.withsix.co";
        $_project_config_resp = file_get_contents($_base_url . "/project-config/config/" . $this->_apikey);
        // get the user's project config
        try {
             if ($_project_config_resp !== false) {
                 $this->_config = json_decode($_project_config_resp);
                 //try_get_rate_limiter_existence 
                 $this->_config->rate_limiter;
                 $this->_sync_project_route($this->_config);
             } else {
                 $this->_config = $this->_sync_project_route();
            }
        } catch (Exception $e) {
            log_message("error", "An error occurred ");
            $this->_config = $this->_sync_project_route();
        }
        $this->_config_secure_log();
        //convert ot std class
        $this->addMiddlewareFilters($this->_config);
    }

    private function _sync_project_route($config=null) {
        // Your logic for syncing project route
        $config = json_decode(json_encode($config), true);
        $routes = Services::routes();
        $raw_routes = $routes->loadRoutes();
        $loaded_get_routes = $raw_routes->getRoutes("get");
        $loaded_post_routes = $raw_routes->getRoutes("post");
        $loaded_patch_routes = $raw_routes->getRoutes("patch");
        $loaded_update_routes = $raw_routes->getRoutes("update");
        $loaded_delete_routes = $raw_routes->getRoutes("delete");
        $all_routes = [];
        foreach ($loaded_get_routes as $key => $value) {
            $all_routes[] = $key;
        }
        foreach ($loaded_post_routes as $key => $value) {
            $all_routes[] = $key;
        }
        foreach ($loaded_patch_routes as $key => $value) {
            $all_routes[] = $key;
        }
        foreach ($loaded_update_routes as $key => $value) {
            $all_routes[] = $key;
        }
        foreach ($loaded_delete_routes as $key => $value) {
            $all_routes[] = $key;
        }
                
        $rlConfigs = [];
        foreach ($all_routes as $path){
            $editedRoute = preg_replace("/\W+/", "~", $path);
         
            if (isset($config["rate_limiter"][$editedRoute]) && is_object($config["rate_limiter"][$editedRoute])){
                
                // Default config has been set earlier on, so skip
                $rlConfigs[$editedRoute] = $config['rate_limiter'][$editedRoute];
                continue;
            }
            $rlConfig = [
                'id' => $editedRoute,
                'route' => $editedRoute,
                'interval' => 60,
                'rate_limit' => 10,
                'last_updated' => time(),
                'created_at' => time(),
                'unique_id' => "host",
                'rate_limit_type' => "ip address",
                'is_active' => false
            ];
            $rlConfigs[$editedRoute] = $rlConfig;

        }
        $_config = json_encode([
            'user_id' => $this->_apikey,
            'rate_limiter' => $rlConfigs,
            'encryption' => [
                'public_key' => "dummy",
                'private_key' => "dummy",
                'use_count' => 0,
                'last_updated' => 0,
                'created_at' => 0,
                'is_active' => false
            ],
            'base_url' => "project",
            'last_updated' => time(),
            'created_at' => time(),
            'encryption_enabled' => $config['encryption_enabled'] ?? false,
            'rate_limiter_enabled' => $config['rate_limiter_enabled'] ?? true
        ]);

        $url = "https://backend.withsix.co/project-config/config/sync-user-config";
        
        // Data to be sent in the POST request (in JSON format)
        
        // Initialize cURL session
        $curl = curl_init();

        // Set cURL options
        curl_setopt_array($curl, array(
            CURLOPT_URL => $url,                    // URL to send the request to
            CURLOPT_RETURNTRANSFER => true,         // Return the response as a string
            CURLOPT_POST => true,                   // Set request method to POST
            CURLOPT_POSTFIELDS => $_config,        // Set the POST data
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/json',   // Set the content type to JSON
                'Content-Length: ' . strlen($_config) // Set content length
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

        return json_decode($response, true);
        
    }

    private function _config_secure_log() {
        // Your logic for secure logging
    }

    private function addMiddlewareFilters($settings)
    {
        $filters = Services::filters();
        $filters->addFilter(SixRateLimiterMiddleware::class, "rate_limiter", "before");
        $filters->addFilter(SixRateLimiterMiddleware::class, "rate_limiter", "after");
        $filters->enableFilter("rate_limiter:". str_replace(":", "8991928389919283",str_replace(',', '8991928689919286', json_encode($settings, JSON_PRETTY_PRINT))). ",". $this->_apikey, "before");
        $filters->enableFilter("rate_limiter:".str_replace(":", "8991928389919283",str_replace(',', '8991928689919286', json_encode($settings, JSON_PRETTY_PRINT))). "," .$this->_apikey, "after");
       
    }
}