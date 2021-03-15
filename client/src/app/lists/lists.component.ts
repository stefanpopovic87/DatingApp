import { Component, OnInit } from '@angular/core';
import { Member } from '../_models/member';
import { Pagination } from '../_models/pagination';
import { MembersService } from '../_services/members.service';

@Component({
  selector: 'app-lists',
  templateUrl: './lists.component.html',
  styleUrls: ['./lists.component.css']
})
export class ListsComponent implements OnInit {
members: Partial<Member[]>;
predicate = 'liked';
pageNumber = 1;
pageSize = 5;
pagination: Pagination;

  constructor(private memberServise: MembersService) { }

  ngOnInit(): void {
    this.loadLikes();
  }

  loadLikes() {
    this.memberServise.getLikes(this.predicate, this.pageNumber, this.pageSize).subscribe(respone => {
    this.members = respone.result;
      this.pagination = respone.pagination;
    })
  }

  pageChanged(event: any) {
    this.pageNumber = event.page;
    this.loadLikes();
  }

}
