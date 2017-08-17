package hello;

import java.util.concurrent.atomic.AtomicLong;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetController {

	private String templt = "Hello,%s!";
	private AtomicLong  counter = new AtomicLong();
	
	@RequestMapping("/greeting")
	public Geeeting greet(@RequestParam(value="name",defaultValue="world") String name){
		return new Geeeting(counter.incrementAndGet(),String.format(templt, name));
	}
}
