package org.javaboy.vhr.controller.system.basic;


import org.javaboy.vhr.model.Position;
import org.javaboy.vhr.model.RespBean;
import org.javaboy.vhr.service.PositionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;

@RestController

@RequestMapping("/system/basic/pos")
public class PositionController {

    @Resource
    PositionService positionService;

    @GetMapping("/")
    public List<Position> getAllPositions(){

        return positionService.getAllPositions();

    }

    @PostMapping("/")
    public RespBean addPostion(@RequestBody Position position){

        if(positionService.addPosition(position)==1) {
            return RespBean.ok("添加成功");
        }

        return RespBean.error("添加失败！");

    }

    @PutMapping("/")
    public RespBean updatePostion(@RequestBody Position position){

        if(positionService.updatePosition(position)==1) {
            return RespBean.ok("更新成功");
        }

        return RespBean.error("更新失败！");

    }
    @DeleteMapping("/{id}")
    public RespBean deletePositon(@PathVariable Integer id){

        if(positionService.deletePositionById(id)==1){
            return RespBean.ok("删除成功");
        }
        return RespBean.error("删除失败");
    }

    @DeleteMapping("/")
    public RespBean deletePositionsByIds(Integer[] ids){
        if(positionService.deletePositionByIds(ids)==ids.length){

            return RespBean.ok("删除成功");
        }
        return RespBean.error("删除失败");

    }
}
