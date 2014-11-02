<?php (defined('BASEPATH')) OR exit('No direct script access allowed');

class Php_ids_model extends CI_Model {

    public function __construct() {

        parent::__construct();

    }

  	public function add_intrusion($data, $table) {

        $this->db->insert($table, $data);

    }

  	public function disable_account($data, $table) {

        $this->db->insert($table, $data);

    }

  	public function ban_ip($data, $table) {

        $this->db->insert($table, $data);

    }

}
