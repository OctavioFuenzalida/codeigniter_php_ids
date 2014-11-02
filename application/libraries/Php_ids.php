<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/**
 * This PHPIDS library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, version 3 of the License, or 
 * (at your option) any later version.
 *
 * This PHPIDS library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this PHPIDS library. If not, see <http://www.gnu.org/licenses/>. 
 *
 * @category        Security
 * @package         PHPIDS library for CodeIgniter
 * @author          Jabo Solutions <http://jabo-solutions.eu>
 * @author          Bas Vermeulen <bas@jabo-solutions.eu>
 * @license         http://www.gnu.org/licenses/lgpl.html LGPL
 * @link            http://jabo-solutions.eu
 * @link            https://hg.jabo-solutions.eu/codeigniter-phpids-library
 * @description     Implementation of PHPIDS (http://php-ids.org): detect and react on intrusions
 */

/**
 * PHP-IDS class
 *
 * @category        Security
 * @package         PHPIDS library for CodeIgniter
 * @author		    Jabo Solutions <http://jabo-solutions.eu>
 * @author          Bas Vermeulen <bas@jabo-solutions.eu>
 * @copyright       2010 Jabo Solutions
 * @license         http://www.gnu.org/licenses/lgpl.html LGPL
 * @version         0.0.1
 * @link            http://jabo-solutions.eu
 * @link            https://hg.jabo-solutions.eu/codeigniter-phpids-library
 * @description     Implementation of PHPIDS (http://php-ids.org): detect and react on intrusions
 */

/**
 * This library is an implementation to connect two great pieces of art. Therefore, a big thank you 
 * goes out to everyone involved in the PHPIDS project, in special Mario Heiderich, Christian Matthies 
 * and Lars H. Strojny. Also everyone involved in the CodeIgniter project from EllisLab Inc, are thanked, 
 * as well as the whole CodeIgniter community for making CodeIgniter such a success!
 */

class Php_ids 
{

    private $CI;                // CodeIgniter instance
    private $init = NULL;       // The init object
    private $redirect = 0;      // Set redirect

    /**
     * Constructor
     *
     * @access      public
     */
    public function __construct()
    {

        // Ignite CI
        $this->CI =& get_instance();

        // Set debug log message
        log_message('debug', 'PHP-IDS Class Initialized');

        // Load config, helper, libraries and model
		$this->CI->load->config('php_ids');
		$this->CI->load->helper('url');
		$this->CI->load->library('email');
		$this->CI->load->library('session');
        $this->CI->load->model('php_ids_model');

        // Set some vars from the config file
        $this->treshold = $this->CI->config->item('treshold');
        $this->ids_url = $this->CI->config->item('ids_url');
        $this->user_id = $this->CI->config->item('user_id');
        $this->ban_duration = $this->CI->config->item('ban_duration');
        $this->disabled_duration = $this->CI->config->item('disabled_duration');
        $this->check_user_agent = $this->CI->config->item('check_user_agent');

        // Reset warning
        $this->CI->session->unset_userdata('ids_warning');

        // Initialize PHP-IDS
        $this->init();

    }

    /**
     * This function includes and initializes PHPIDS.
     *
     * @access      public
     * @return      boolean
     */
    public function init()
    {

        // Set include path for IDS and store old one
        $path = get_include_path();
        set_include_path($this->ids_url);

        // Require the init script
        require_once($this->ids_url . 'IDS/Init.php');

        // Add request url and user agent
        $_REQUEST['IDS_request_uri'] = $_SERVER['REQUEST_URI'];
        if(isset($_SERVER['HTTP_USER_AGENT']) && $this->check_user_agent != FALSE)
        {
            $_REQUEST['IDS_user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        }

        // Init the PHPIDS 
        $this->init = IDS_Init::init($this->ids_url . 'IDS/Config/Config.ini.php');
        $ids        = new IDS_Monitor($_REQUEST, $this->init);
        $result     = $ids->run();

        // Re-set include path
        set_include_path($path);

        if (!$result->isEmpty())
        {
            $this->__react($result);
        }

        // Redirect after session kill
        if($this->redirect == 1)
        {
            redirect('/');
        } 
        else 
        {    
            return TRUE;
        }

    }

    /**
     * This function reacts on the values in the incoming
     * results array. Depending on the impact value and 
     * the treshold settings certain actions are performed.
     *
     * @access      private
     * @param       IDS_Report $result
     * @return      boolean
     */
    private function __react(IDS_Report $result)
    {

        // Update session
        $new = $this->CI->session->userdata('ids_impact') + $result->getImpact();
        $this->CI->session->set_userdata('ids_impact', $new);
        $impact = $new;

        // Log
        if ($impact >= $this->treshold['log'] && $this->treshold['log'] != 0)
        {
	        $this->__log($result, $impact);
        }	

        // Warn the user
        if ($impact >= $this->treshold['warn'] && $this->treshold['warn'] != 0)
        {
	        $this->__warn();
        }

        // Send an email alert
        if ($impact >= $this->treshold['mail'] && $this->treshold['mail'] != 0)
        {
	        $this->__mail($result, $impact);
        }

        // Kill the session
        if ($impact >= $this->treshold['kill'] && $this->treshold['kill'] != 0)
        {
	        $this->__kill();
        }

        // Disable the user's account 
        if ($impact >= $this->treshold['disable_account'] && $this->treshold['disable_account'] != 0)
        {
            if($this->user_id > 0)
            {
	            $this->__disable_account($result, $impact);
            }
        }

        // Ban the IP
        if ($impact >= $this->treshold['ban_ip'] && $this->treshold['ban_ip'] != 0)
        {
	        $this->__ban_ip($result, $impact);
        }

        // Send a text alert
        if ($impact >= $this->treshold['text'] && $this->treshold['text'] != 0)
        {
	        // TODO $this->__text($result);
        }

        return TRUE;

    }

    /**
     * This function prepares the intrusion data
     *
     * @access      private
     * @param       array $results
     * @param       string $impact
     * @return      array $intrusion
     */
    private function __intrusion(IDS_Report $result, $impact)
    {

	    // Get description
        foreach ($result as $event)
        {

            $description = '';
            $intrusion = '';

	        // Get the tags	
	        $tags = implode(", ",$event->getTags());

            // Set the description
	        foreach ($event as $filter)
            {
	            $description .= "Description: ".$filter->getDescription()." | ";
	            $description .= "Tags: ".join(', ', $filter->getTags())." | ";
	            $description .= "ID: ".$filter->getId()."<br />";
		    }

            // Set data
            $intrusion = array(
                'name'              => $event->getName(),
                'value'             => htmlentities($event->getValue()),
                'page'              => current_url(),
                'tags'              => $tags,
                'description'       => $description,
                'user_id'           => $this->CI->session->userdata($this->user_id),
                'user_ip'           => $this->CI->input->ip_address(),
                'user_browser'      => $this->CI->input->user_agent(),
                'session_id'        => $this->CI->session->userdata('session_id'),
                'server_ip'         => $_SERVER['SERVER_ADDR'],
                'event_impact'      => $event->getImpact(),
                'session_impact'    => $impact,
                'created'           => date('Y-m-d H:i:s')
            );

        }

        return $intrusion;

    }

    /**
     * This function writes an entry about the intrusion
     * to the intrusion table
     *
     * @access      private
     * @param       array $results
     * @param       string $impact
     * @return      boolean
     */
    private function __log($result, $impact)
    {

        // Set debug log message
        log_message('debug', 'PHP-IDS reaction: log');

        // Get intrusion data
        $data = $this->__intrusion($result, $impact);

        // Add this intrusion into the database
        $this->CI->php_ids_model->add_intrusion($data, $this->CI->config->item('intrusions_table'));

        return TRUE;

    }

    /**
     * This function warns the user
     *
     * @access      private
     * @return      boolean
     */
    private function __warn()
    {

        // Set debug log message
        log_message('debug', 'PHP-IDS reaction: warn');

        // Set warning
        $this->CI->session->set_userdata('ids_warning', $this->CI->config->item('message_warning'));

        /**
         * You can display this warning wherever you want, use
         * the following code example in a view or grab the session
         * data in your controller and parse it as a variable to 
         * your view.
         * 
         * <?php 
         * // PHPIDS Warning
         * $ids_warning = $this->session->userdata('ids_warning');
         * if(isset($ids_warning) && $ids_warning != '') {
         *     echo "<div id=\"warning\">$ids_warning</div>";
         * }
         * ?>
         */

        return TRUE;

    }

    /**
     * This function sends an email
     *
     * @access      private
     * @param       array $results
     * @param       string $impact
     * @return      boolean
     */
    private function __mail($result, $impact)
    {

        // Set debug log message
        log_message('debug', 'PHP-IDS reaction: email');

        // Get intrusion data
        $data = $this->__intrusion($result, $impact);

        // Set message
        $message  = "The following attack has been detected by PHPIDS<br /><br />";
        $message .= "<strong>Name:</strong> ".$data['name']."<br />";
        $message .= "<strong>Value:</strong> ".$data['value']."<br />";
        $message .= "<strong>Page:</strong> ".$data['page']."<br />";
        $message .= "<strong>Description:</strong><br />".$data['description'];
        $message .= "<strong>User ID:</strong> ".$data['user_id']."<br />";
        $message .= "<strong>User IP:</strong> ".$data['user_ip']."<br />";
        $message .= "<strong>User browser:</strong> ".$data['user_browser']."<br />";
        $message .= "<strong>Session ID:</strong> ".$data['session_id']."<br />";
        $message .= "<strong>Server IP:</strong> ".$data['server_ip']."<br />";
        $message .= "<strong>Event impact:</strong> ".$data['event_impact']."<br />";
        $message .= "<strong>Session impact:</strong> ".$data['session_impact']."<br />";
        $message .= "<strong>Date:</strong> ".$data['created']."<br />";

        $this->CI->load->library('email');
        $this->CI->email->from($this->CI->config->item('email_address'), 'PHPIDS library');
        $this->CI->email->to($this->CI->config->item('email_address'));
        $this->CI->email->subject('PHPIDS alert from server '.$data['server_ip']);
        $this->CI->email->message($message);

        if(!$this->CI->email->send())
        {
            // Log error
            // TODO
        }

        return TRUE;

    }

    /**
     * This function adds the user ID into the disabled accounts table.
     *
     * @access      private
     * @param       array $results
     * @param       string $impact
     * @return      boolean
     */
    private function __disable_account(IDS_Report $result, $impact)
    {

        // Set debug log message
        log_message('debug', 'PHP-IDS reaction: disable account');

        // Get intrusion data
        $intrusion = $this->__intrusion($result, $impact);
        $start = date('YmdHis');
        $end = date('YmdHis', mktime(
            date("H") + $this->disabled_duration['hours'], 
            date("i") + $this->disabled_duration['minutes'],     
            date("s") + $this->disabled_duration['seconds'], 
            date("m") + $this->disabled_duration['months'], 
            date("d") + $this->disabled_duration['days'], 
            date("Y") + $this->disabled_duration['years']
        ));

        // Set data
        $data = array(
            'user_id' => $intrusion['user_id'],
            'reason' => $intrusion['description'],
            'start' => $start,
            'end' => $end,
        );

        // Disable the account
        $this->CI->php_ids_model->disable_account($data, $this->CI->config->item('disabled_table'));

        return TRUE;

    }

    /**
     * This function adds the user ID into the banned ip's table. 
     *
     * @access      private
     * @param       array $results
     * @param       string $impact
     * @return      boolean
     */
    private function __ban_ip(IDS_Report $result, $impact)
    {

        // Set debug log message
        log_message('debug', 'PHP-IDS reaction: ban ip');

        // Get intrusion data
        $intrusion = $this->__intrusion($result, $impact);
        $start = date('YmdHis');
        $end = date('YmdHis', mktime(
            date("H") + $this->ban_duration['hours'], 
            date("i") + $this->ban_duration['minutes'],     
            date("s") + $this->ban_duration['seconds'], 
            date("m") + $this->ban_duration['months'], 
            date("d") + $this->ban_duration['days'], 
            date("Y") + $this->ban_duration['years']
        ));

        // Set data
        $data = array(
            'ip' => $intrusion['user_ip'],
            'reason' => $intrusion['description'],
            'start' => $start,
            'end' => $end,
        );

        // Disable the account
        $this->CI->php_ids_model->ban_ip($data, $this->CI->config->item('bans_table'));

        return TRUE;

    }

    /**
     * This function kills the session
     *
     * @access      private
     * @return      boolean
     */
    private function __kill()
    {

        // Set debug log message
        log_message('debug', 'PHP-IDS reaction: kill');

	    // Destroy this session to make sure the user is logged out
        $this->CI->session->sess_destroy();

        // Set redirect to TRUE
        $this->redirect = 1;

        return TRUE;

    }

    /**
     * This function sends a text
     *
     * @access      private
     * @return      boolean
     */
    private function __text()
    {

        // Set debug log message
        log_message('debug', 'PHP-IDS reaction: text');

        // TODO: Plan is to use http://www.textmagic.com/ for this functionality.

        return TRUE;

    }

}

/* End of file Php_ids.php */
/* Location: ./application/libraries/Php_ids.php */
