pub struct Hmac {
    pub result: [u8; 32],
}

impl Hmac {
	pub fn new() -> Hmac{
		Hmac {result: [0u8; 32]}
	}
	
	pub fn update_result(&mut self, hmac: [u8; 32]){
		self.result = hmac;
	}
}